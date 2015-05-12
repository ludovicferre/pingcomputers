using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections;
using System.Text;
using System.Data;
using System.Data.SqlClient;
using System.Threading;
using System.Net.NetworkInformation;
using Altiris.NS.Logging;
using Altiris.NS.Scoping;
using Altiris.NS.Security;
using Altiris.NS.StandardItems.Collection.Scoping;
using Altiris.NS.ResourceManagement;
using Symantec.CWoC.APIWrappers;

namespace Symantec.CWoC {
    class PingComputers {
	
		public static readonly string sql = @"
--   set rowcount 500
select distinct(i.[Host Name] + '.' + i.[Primary DNS Suffix]) -- r._ResourceGuid
  from Inv_Client_Task_Resources r
  join Inv_AeX_AC_TCPIP i
    on r._ResourceGuid = i._resourceguid
 where LastRegistered < GETDATE() - 14
   and HasTaskAgent = 1
";

		public static void Main() {
			try {
				SecurityContextManager.SetContextData();
				DataTable computers = DatabaseAPI.GetTable(sql);
				
				Pinger p = new Pinger();
				
				foreach (DataRow r in computers.Rows) {
						Pinger.HostQueue.Enqueue(r[0].ToString());
				}

				Collection<Thread> pool = new Collection<Thread>();
				for (int i = 0; i < 50; i++) {
					Thread t = new Thread(new ThreadStart(p.RunPing));
					t.Start();
					pool.Add(t);
				}
				
				Console.WriteLine("Currently running {0} threads, {1} queued hostnames, {2} tested hostnames.", pool.Count.ToString(), Pinger.HostQueue.Count.ToString(), Pinger.ResultQueue.Count.ToString());
				
				foreach (Thread t in pool) {
					Console.Write(".");
					t.Join();
				}
				Console.WriteLine();
				
				Console.WriteLine("\n\rDequeueing results (we have {0} entries)...", Pinger.ResultQueue.Count.ToString());
				
				KeyValuePair<string, int> results = new KeyValuePair<string, int>();
				while (Pinger.ResultQueue.Count > 0) {
					results = (KeyValuePair<string, int>) Pinger.ResultQueue.Dequeue();
					if (results.Value != 0)
						Console.WriteLine("{1} for host {0}.", results.Key, (results.Value != 0) ? "SUCCESS" : "Failure");
				}				
				
			} catch (Exception e) {
				// EventLog.ReportError(String.Format("{0}\n{1}", e.Message, e.InnerException));
				Console.WriteLine("{0}\n{1}", e.Message, e.InnerException);
			}
		}
    }
	class Pinger {
		private static Queue baseHostQueue;
		public static Queue HostQueue;
		
		private static Queue baseResultQueue;
		public static Queue ResultQueue;
		
		public Pinger() {
			// Make sure the queues is initialized and synched
			baseResultQueue = new Queue();
			ResultQueue = Queue.Synchronized(baseResultQueue);
			
			baseHostQueue = new Queue();
			HostQueue = Queue.Synchronized(baseHostQueue);
			
		}
	
		public void RunPing () {
			string hostname = "";
			while ((hostname = GetHost()) != "")  {
				// Do the ping
				string tid =  Thread.CurrentThread.ManagedThreadId.ToString();
				try {
					Ping ping = new Ping();
					
					// Console.Write("Pinging... Entries in queue = {0}, Results enqueued = {1} \t[tid = {2}]\r", HostQueue.Count.ToString("#####") , ResultQueue.Count.ToString("#####"), tid);
					PingReply result = ping.Send(hostname);

					if (result.Status == IPStatus.Success) {
						SaveResult(hostname, 1);
						// Console.WriteLine("Ping succedded to {0} ({1}), round trip time = {2} ms. [tid = {3}]", hostname, result.Address.ToString(), result.RoundtripTime, tid);
					} else {
						SaveResult(hostname, 0);	
						// Console.WriteLine("Failed to ping host {0} (tid={1})", hostname, tid);
					}
				} catch {
					SaveResult(hostname, 0);
					// Console.WriteLine("Failed to ping host {0} (tid={1})", hostname, tid);
				}
			}
		}
		public string GetHost() {
			// Get hostname from a queue
			if (HostQueue.Count > 0) 
				return HostQueue.Dequeue().ToString();
			else
				return "";
		}
		public void SaveResult(string hostname, int status) {
			KeyValuePair<string, int> kvp = new KeyValuePair<string, int>(hostname, status);
			ResultQueue.Enqueue(kvp);
		}
	}
}
