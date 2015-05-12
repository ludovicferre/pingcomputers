using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections;
using System.ServiceProcess;
using System.Diagnostics;
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
-- Get TS/PS computers for test
select distinct(s.[Host Name] + '.' + s.[Primary DNS Suffix])
  from vSiteServices s
 order by s.[Host Name] + '.' + s.[Primary DNS Suffix]

/*
select distinct(i.[Host Name] + '.' + i.[Primary DNS Suffix]) -- r._ResourceGuid
  from Inv_Client_Task_Resources r
  join Inv_AeX_AC_TCPIP i
    on r._ResourceGuid = i._resourceguid
 where LastRegistered < GETDATE() - 14
   and HasTaskAgent = 1
*/
";

		public static void Main() {
			try {
				SecurityContextManager.SetContextData();
				DataTable computers = DatabaseAPI.GetTable(sql);
				
				Pinger p = new Pinger();
				
				foreach (DataRow r in computers.Rows) {
						p.HostQueue.Enqueue(r[0].ToString());
				}


				Collection<Thread> pool = new Collection<Thread>();
				
				int pool_depth = p.HostQueue.Count / 10;
				
				// Make sure we don't have more than 50 threads
				if (pool_depth > 50)
					pool_depth = 50;
					
				// and at least 1 thread running
				if (pool_depth == 0)
					pool_depth = 1;
				
				for (int i = 0; i < pool_depth; i++) {
					Thread t = new Thread(new ThreadStart(p.RunPing));
					t.Start();
					pool.Add(t);
				}
				
				Console.WriteLine("Currently running {0} threads, {1} queued hostnames, {2} tested hostnames.", pool.Count.ToString(), p.HostQueue.Count.ToString(), p.ResultQueue.Count.ToString());
				
				foreach (Thread t in pool) {
					Console.Write(".");
					t.Join();
				}
				Console.WriteLine();
				Console.WriteLine("\n\rDequeueing results (we have {0} entries)...", p.ResultQueue.Count.ToString());
				
				// Move to stage 2: check the Altiris Agent status if possible
				ServiceChecker sc = new ServiceChecker();

				KeyValuePair<string, int> results = new KeyValuePair<string, int>();
				while (p.ResultQueue.Count > 0) {
					results = (KeyValuePair<string, int>) p.ResultQueue.Dequeue();
					if (results.Value != 0) {
						Console.WriteLine("{1} for host {0}.", results.Key, (results.Value != 0) ? "SUCCESS" : "Failure");
						sc.HostQueue.Enqueue(results.Key);
					}
				}
				
				// All reachable computers are available for the ServiceChecker - run multi-threaded check now.
				
				// Reset the thread pool and limit
				pool.Clear();
				pool_depth = sc.HostQueue.Count / 5;
				
				// Make sure we don't have more than 50 threads
				if (pool_depth > 50)
					pool_depth = 50;
					 
				// and at least 1 thread running
				if (pool_depth == 0)
					pool_depth = 1;

				for (int i = 0; i < pool_depth; i++) {
					Thread t = new Thread(new ThreadStart(sc.RunCheck));
					t.Start();
					pool.Add(t);
				}

				Console.WriteLine("Currently running {0} threads, {1} queued hostnames, {2} tested hostnames.", pool.Count.ToString(), sc.HostQueue.Count.ToString(), sc.ResultQueue.Count.ToString());
				
				foreach (Thread t in pool) {
					Console.Write(".");
					t.Join();
				}
				Console.WriteLine();
				Console.WriteLine("\n\rDequeueing results (we have {0} entries)...", sc.ResultQueue.Count.ToString());
				
				KeyValuePair<string, string> sc_results = new KeyValuePair<string, string>();
				while (sc.ResultQueue.Count > 0) {
					sc_results = (KeyValuePair<string, string>) sc.ResultQueue.Dequeue();
					Console.WriteLine("Altiris Agent service status for host {0}: {1}", sc_results.Key, sc_results.Value);
				}

			} catch (Exception e) {
				// EventLog.ReportError(String.Format("{0}\n{1}", e.Message, e.InnerException));
				Console.WriteLine("{0}\n{1}", e.Message, e.InnerException);
			}
		}
    }
	class Pinger {
		private Queue baseHostQueue;
		public Queue HostQueue;
		
		private Queue baseResultQueue;
		public Queue ResultQueue;
		
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

	class ServiceChecker {
		private Queue baseHostQueue;
		public Queue HostQueue;
		
		private Queue baseResultQueue;
		public Queue ResultQueue;
		
		private string service_name;
		
		public ServiceChecker(string service) {
			service_name = service;
			init();
		}
		
		public ServiceChecker() {
			service_name = "AeXNSClient";
			init();
		}
		
		private void init() {
			baseResultQueue = new Queue();
			ResultQueue = Queue.Synchronized(baseResultQueue);
			
			baseHostQueue = new Queue();
			HostQueue = Queue.Synchronized(baseHostQueue);
		}
		
		public void RunCheck() {
			string hostname = "";
			while ((hostname = GetHost()) != "")  {
				// Do the ping
				string tid =  Thread.CurrentThread.ManagedThreadId.ToString();
				try {
					ServiceController sc = new ServiceController(service_name, hostname);
					SaveResult(hostname, sc.Status.ToString());
				} catch {
					SaveResult(hostname, "ERROR");
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

		public void SaveResult(string hostname, string status) {
			KeyValuePair<string, string> kvp = new KeyValuePair<string, string>(hostname, status);
			ResultQueue.Enqueue(kvp);
		}
	}
	
}
