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
select distinct(s.[Host Name] + '.' + s.[Primary DNS Suffix]), s.Guid
  from vSiteServices s
 order by s.[Host Name] + '.' + s.[Primary DNS Suffix]
*/
set rowcount 500
select distinct (r._ResourceGuid), i.[Host Name] + '.' + i.[Primary DNS Suffix]
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
				
				Pinger pinger = new Pinger();
				
				foreach (DataRow r in computers.Rows) {
					HostData d = new HostData(r[0].ToString(), r[1].ToString());
					pinger.HostQueue.Enqueue(d);
				}

				// Create a thread pool to run the ping task
				ThreadPool pinger_thread_pool = new ThreadPool();
				Thread pinger_status_thread = new Thread(new ThreadStart(pinger.PrintStatus));

				pinger_status_thread.Start();
				pinger_thread_pool.PoolDepth = pinger.HostQueue.Count / 10;
				pinger_thread_pool.StartAll(pinger.RunPing);
				pinger_status_thread.Join();
				pinger_thread_pool.JoinAll();

				Console.WriteLine("\n\rDequeueing results (we have {0} entries)...", pinger.ResultQueue.Count.ToString());
			
				// Move to stage 2: check the Altiris Agent status if possible
				ServiceChecker sc = new ServiceChecker();

				TestResult result = new TestResult();
				HostData hostdata = new HostData();
				while (pinger.ResultQueue.Count > 0) {
					result = (TestResult) pinger.ResultQueue.Dequeue();
					if (result.status == "1")
						hostdata = new HostData(result.host_name, result.host_guid);
						sc.HostQueue.Enqueue(hostdata);
				}

				ThreadPool sc_thread_pool = new ThreadPool();
				Thread sc_status_thread = new Thread(new ThreadStart(sc.PrintStatus));

				sc_status_thread.Start();
				sc_thread_pool.PoolDepth = sc.HostQueue.Count / 5;				
				sc_thread_pool.StartAll(sc.RunCheck);
				sc_status_thread.Join();
				sc_thread_pool.JoinAll();
				
				Console.WriteLine("\n\nDequeueing results (we have {0} entries)...", sc.ResultQueue.Count.ToString());
				sc.PrintResults();

			} catch (Exception e) {
				// EventLog.ReportError(String.Format("{0}\n{1}", e.Message, e.InnerException));
				Console.WriteLine("{0}\n{1}", e.Message, e.InnerException);
			}
            Timer.Stop();
		}
		
    }

	class HostData {
		public string host_name;
		public string host_guid;
		
		public HostData() {
			host_name = "";
			host_guid = "";
		}
		
		public HostData(string name, string guid) {
			host_name = name;
			host_guid = guid;
		}
	}
	
	class TestResult : HostData {
		public string status;
		
		public TestResult() {
			status = "";
		}
		
		public TestResult(string _status) {
			status = _status;
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
				Console.Write(".");
			}
			Console.WriteLine(".");
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

		public void StoreResult(TestResult result) {
			ResultQueue.Enqueue(result);
		}

		public HostData GetHostdata() {
			// Get hostname from a queue
			if (HostQueue.Count > 0) 
				return (HostData) HostQueue.Dequeue();
			else
				return new HostData();
		}
	}

	class Pinger : QueueWorker {	
		public void RunPing () {
			while (true)  {
				HostData hostdata = GetHostdata();
				if (hostdata.host_name == "" && hostdata.host_guid == "")
					break;
				TestResult testresult = new TestResult();
				try {
					testresult.host_name = hostdata.host_name;
					testresult.host_guid = hostdata.host_guid;
					
					Ping ping = new Ping();
					PingReply result = ping.Send(hostdata.host_name);

					if (result.Status == IPStatus.Success) {
						testresult.status = "1";
						StoreResult(testresult);
					} else {
						testresult.status = "0";
						StoreResult(testresult);	
					}
				} catch (Exception e){
					testresult.status = e.Message;
					StoreResult(testresult);
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
			while (true)  {
				HostData hostdata = GetHostdata();
				if (hostdata.host_name == "" && hostdata.host_guid == "")
					break;
				TestResult testresult = new TestResult();
				try {
					testresult.host_name = hostdata.host_name;
					testresult.host_guid = hostdata.host_guid;
					ServiceController sc = new ServiceController(service_name, hostdata.host_name);
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
							Console.WriteLine("Failed to start the Altiris Agent service {0} times on {1}...", (i + 1).ToString(), testresult.host_name);
						}
					}
					testresult.status = sc.Status.ToString();
					StoreResult(testresult);
				} catch (Exception e) {
					testresult.status = e.Message;
					StoreResult(testresult);
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
