using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections;
using System.Text;
using System.Data;
using System.Data.SqlClient;
using System.Threading;
using System.Net.NetworkInformation;
//using Altiris.NS.Logging;
//using Altiris.NS.Scoping;
//using Altiris.NS.Security;
//using Altiris.NS.StandardItems.Collection.Scoping;
//using Altiris.NS.ResourceManagement;
//using Symantec.CWoC.APIWrappers;

namespace Symantec.CWoC {
    class PingComputers {
		public static void Main() {
			try {
				// SecurityContextManager.SetContextData();
				// DataTable scope_collections = DatabaseAPI.GetTable("select top 10 * from sys.objects");
				
				Pinger p = new Pinger();
				Pinger.HostQueue.Enqueue("www.google.com");
				Pinger.HostQueue.Enqueue("www.symantec.com");
				Pinger.HostQueue.Enqueue("www.cisco.com");
				Pinger.HostQueue.Enqueue("www.yahoo.com");
				Pinger.HostQueue.Enqueue("www.apple.com");
				Pinger.HostQueue.Enqueue("www.ibm.com");
				Pinger.HostQueue.Enqueue("www.linux.org");
				Pinger.HostQueue.Enqueue("www.15-cloud.fr");
				
				Collection<Thread> pool = new Collection<Thread>();
				for (int i = 0; i < 4; i++) {
					Thread t = new Thread(new ThreadStart(p.RunPing));
					t.Start();
					pool.Add(t);
				}
				
				
				Thread s = new Thread(new ThreadStart(p.RunPing));
				s.Start();
				
				// p.RunPing();
				
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
					PingReply result = ping.Send(hostname);
					
					if (result.Status == IPStatus.Success) {
						Console.WriteLine("Ping succedded to {0} ({1}), round trip time = {2} ms. [tid = {3}]", hostname, result.Address.ToString(), result.RoundtripTime, tid);
					} else {
						Console.WriteLine("Failed to ping host {0} (tid={1})", hostname, tid);
					}
				} catch {
					Console.WriteLine("Failed to ping host {0} (tid={1})", hostname, tid);
				}
					SaveResult(hostname, 0);	
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
		
		}
	}
}
