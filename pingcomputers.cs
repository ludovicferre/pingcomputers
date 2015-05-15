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
using Symantec.CWoC.APIWrappers;

namespace Symantec.CWoC {
    class PingComputers {
	
		public static readonly string sql = @"
/*
-- Get TS/PS computers for test
select distinct(s.[Host Name] + '.' + s.[Primary DNS Suffix])
  from vSiteServices s
 order by s.[Host Name] + '.' + s.[Primary DNS Suffix]
*/
set rowcount 500
select distinct(i.[Host Name] + '.' + i.[Primary DNS Suffix]) -- r._ResourceGuid
  from Inv_Client_Task_Resources r
  join Inv_AeX_AC_TCPIP i
    on r._ResourceGuid = i._resourceguid
 where LastRegistered < GETDATE() - 7
   and HasTaskAgent = 1

";

		public static void Main() {
			Timer.Init();
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
					
				p.ThreadPoolDepth = pool_depth;
				
				for (int i = 0; i < pool_depth; i++) {
					Thread t = new Thread(new ThreadStart(p.RunPing));
					t.Start();
					pool.Add(t);
				}
				
				Thread m = new Thread(new ThreadStart(p.PrintStatus));
				m.Start();
				m.Join();

				foreach (Thread t in pool) {
					Console.Write(".");
					t.Join(1000);
				}

				Console.WriteLine("\n\rDequeueing results (we have {0} entries)...", p.ResultQueue.Count.ToString());
			
				// Move to stage 2: check the Altiris Agent status if possible
				ServiceChecker sc = new ServiceChecker();

				KeyValuePair<string, string> results = new KeyValuePair<string, string>();
				while (p.ResultQueue.Count > 0) {
					results = (KeyValuePair<string, string>) p.ResultQueue.Dequeue();
					if (results.Value == "1") {
						sc.HostQueue.Enqueue(results.Key);
					}
				}
								
				// Reset the thread pool and limit
//				pool.Clear();
				pool_depth = sc.HostQueue.Count / 5;

/*				
				// Make sure we don't have more than 50 threads
				if (pool_depth > 50)
					pool_depth = 50;
					 
				// and at least 1 thread running
				if (pool_depth == 0)
					pool_depth = 1;
					
				sc.ThreadPoolDepth = pool_depth;

				for (int i = 0; i < pool_depth; i++) {
					Thread t = new Thread(new ThreadStart(sc.RunCheck));
					t.Start();
					pool.Add(t);
				}
*/					
				Thread n = new Thread(new ThreadStart(sc.PrintStatus));
				n.Start();
		
				ThreadPool tp = new ThreadPool();
				tp.PoolDepth = pool_depth;
				
				tp.StartAll(sc.RunCheck);
				Console.WriteLine("Waiting for threads to converge back...");

				n.Join();
				tp.JoinAll();

				foreach (Thread t in pool) {
					Console.Write("!");
					t.Join(1000);
				}
				Console.WriteLine("\n\nDequeueing results (we have {0} entries)...", sc.ResultQueue.Count.ToString());
				sc.PrintResults();

			} catch (Exception e) {
				// EventLog.ReportError(String.Format("{0}\n{1}", e.Message, e.InnerException));
				Console.WriteLine("{0}\n{1}", e.Message, e.InnerException);
			}
            Timer.Stop();
		}
		
    }


	class ThreadPool {
		private int pool_depth;
		public Collection<Thread> pool;
				
		public ThreadPool() {
			pool_depth = 10;
			pool = new Collection<Thread>();
		}
		
		public int PoolDepth {
			set {
				if (value < 1)
					pool_depth = 1;
				else if (value > 50)
					pool_depth = 50;
				else
					pool_depth = value;
			}
			get {
				return pool_depth;
			}
		}
		
		public void StartAll(ThreadStart st) {
			for (int i = 0; i < pool_depth; i++) {
				Thread t = new Thread(st);
				t.Start();
				Add(t);
			}
		}
		
		private void Add(Thread t) {
			pool.Add(t);
		}
		
		public void JoinAll() {
			foreach(Thread t in pool) {
				t.Join(1000);
			}
		}
	}
	
	class QueueWorker {
		private Queue baseHostQueue;
		public Queue HostQueue;
		public int ThreadPoolDepth;
		
		private Queue baseResultQueue;
		public Queue ResultQueue;
	
		public QueueWorker(){
			init();
		}
		
		public 	void init() {
			ThreadPoolDepth = 0;
			baseResultQueue = new Queue();
			ResultQueue = Queue.Synchronized(baseResultQueue);
			
			baseHostQueue = new Queue();
			HostQueue = Queue.Synchronized(baseHostQueue);
		}
		
		public void PrintStatus() {
			while (HostQueue.Count > 0) {
				Console.Write("Currently running {0} threads, {1} queued hostnames, {2} tested hostnames.\r", ThreadPoolDepth.ToString(), HostQueue.Count.ToString(), ResultQueue.Count.ToString());
				Thread.Sleep(1000);
			}
			Console.WriteLine("Currently running {0} threads, {1} queued hostnames, {2} tested hostnames.", ThreadPoolDepth.ToString(), HostQueue.Count.ToString(), ResultQueue.Count.ToString());

		}

		public void PrintResults() {
			foreach (KeyValuePair<string, string> kvp in ResultQueue) {
				Console.WriteLine("Status = {1} for host {0}.", kvp.Key, kvp.Value);
			}
		}

		public virtual void SaveResults() {}

		public void StoreResult(string hostname, string status) {
			KeyValuePair<string, string> kvp = new KeyValuePair<string, string>(hostname, status);
			ResultQueue.Enqueue(kvp);
		}

		public string GetHostname() {
			// Get hostname from a queue
			if (HostQueue.Count > 0) 
				return HostQueue.Dequeue().ToString();
			else
				return "";
		}
	}

	class Pinger : QueueWorker {	
		public void RunPing () {
			string hostname = "";
			while ((hostname = GetHostname()) != "")  {
				// string tid =  Thread.CurrentThread.ManagedThreadId.ToString();
				try {
					Ping ping = new Ping();
					
					// Console.Write("Pinging... Entries in queue = {0}, Results enqueued = {1} \t[tid = {2}]\r", HostQueue.Count.ToString("#####") , ResultQueue.Count.ToString("#####"), tid);
					PingReply result = ping.Send(hostname);

					if (result.Status == IPStatus.Success) {
						StoreResult(hostname, "1");
						// Console.WriteLine("Ping succedded to {0} ({1}), round trip time = {2} ms. [tid = {3}]", hostname, result.Address.ToString(), result.RoundtripTime, tid);
					} else {
						StoreResult(hostname, "0");	
						// Console.WriteLine("Failed to ping host {0} (tid={1})", hostname, tid);
					}
				} catch {
					StoreResult(hostname, "Could not ping");
					// Console.WriteLine("Failed to ping host {0} (tid={1})", hostname, tid);
				}
			}
		}

		public override void SaveResults() {
		}
	}

	class ServiceChecker : QueueWorker {
		private string service_name;
		public ServiceChecker(string service) {
			service_name = service;
		}		
		public ServiceChecker() {
			service_name = "AeXNSClient";
		}		
		
		public void RunCheck() {
			string hostname = "";
			while ((hostname = GetHostname()) != "")  {
				// Do the ping
				string tid =  Thread.CurrentThread.ManagedThreadId.ToString();
				try {
					ServiceController sc = new ServiceController(service_name, hostname);
					if (sc.Status == ServiceControllerStatus.Stopped) {
						// Start the service if it is stopped.
						int i = 0;
						while (i < 5) {
							sc.Start();
							i++;
							sc.Refresh();
							if (sc.Status == ServiceControllerStatus.Running)
								break;
						}
						if (i > 4) {
							Console.WriteLine("Failed to start the Altiris Agent service {0} times on {1}...", (i + 1).ToString(), hostname);
						}
					}
					StoreResult(hostname, sc.Status.ToString());
				} catch {
					StoreResult(hostname, "EXCEPTION");
				}
			}
		}
		
		public override void SaveResults() {
		}
	}

    class Timer {
        private static Stopwatch chrono;

        public static void Init() {
            chrono = new Stopwatch();
            chrono.Start();
        }

        public static void Start() {
            chrono.Start();
        }
        public static void Stop() {
            chrono.Stop();
        }
        public static string tickCount() {
            return chrono.ElapsedTicks.ToString();
        }
        public static string duration() {
            return chrono.ElapsedMilliseconds.ToString();
        }
    }
	
}
