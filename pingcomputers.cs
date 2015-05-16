using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections;
using System.ServiceProcess;
//using System.Diagnostics;
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
SELECT i.fqdn, c.Guid
  FROM [vComputerResource] c
 INNER JOIN (
			select [ResourceGuid], max([ModifiedDate]) as LatestInventoryDate from dbo.ResourceUpdateSummary  
			where InventoryClassGuid = '9E6F402A-6A45-4CBA-9299-C2323F73A506'     
			group by [ResourceGuid]  
		) as dt
	ON c.Guid = dt.ResourceGuid
  LEFT JOIN Inv_AeX_AC_IDentification i
    ON c.Guid = i._ResourceGuid
 WHERE c.IsManaged = 1 
   AND dt.LatestInventoryDate < getdate() - 7
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
				pinger_thread_pool.PoolDepth = pinger.HostQueue.Count / 10;
				pinger.ThreadPoolDepth = pinger_thread_pool.PoolDepth;

				pinger_status_thread.Start();
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
					if (result.status == "1") {
						hostdata = new HostData(result.host_name, result.host_guid);
						sc.HostQueue.Enqueue(hostdata);
					}
				}

				ThreadPool sc_thread_pool = new ThreadPool();
				Thread sc_status_thread = new Thread(new ThreadStart(sc.PrintStatus));
				sc_thread_pool.PoolDepth = sc.HostQueue.Count / 5;
				sc.ThreadPoolDepth = sc_thread_pool.PoolDepth;

				sc_status_thread.Start();
				sc_thread_pool.StartAll(sc.RunCheck);
				sc_status_thread.Join();
				sc_thread_pool.JoinAll();
				
				Console.WriteLine("\n\nDequeueing results (we have {0} entries)...", sc.ResultQueue.Count.ToString());
				//sc.PrintResults();

			} catch (Exception e) {
				EventLog.ReportError(String.Format("{0}\n{1}", e.Message, e.InnerException));
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
		private Queue baseResultQueue;
		public Queue ResultQueue;
	
		public int ThreadPoolDepth;
		public bool DatabaseReady;

		public QueueWorker(){
			init();
		}
		
		public 	void init() {
			if (CreateTable() == 0)
				DatabaseReady = true;
			else
				DatabaseReady = false;

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
			foreach (TestResult result in ResultQueue) {
				Console.WriteLine("Status = {0} for computer {1}::{2}.", result.status, result.host_guid, result.host_name);
			}
		}

		public void StoreResult(TestResult result, string event_type) {
			ResultQueue.Enqueue(result);
			RecordEvent(result, event_type);
		}

		public HostData GetHostdata() {
			// Get hostname from a queue
			if (HostQueue.Count > 0) 
				return (HostData) HostQueue.Dequeue();
			else
				return new HostData();
		}

		public void RecordEvent(TestResult result, string event_type) {
			result.status = result.status.Replace("'", "\"");
			string sql = String.Format("insert CWoC_Pinger_Event(timestamp, resourceguid, hostname, eventtype, [status]) values (getdate(), '{0}', '{1}', '{2}', '{3}')"
							, result.host_guid
							, result.host_name
							, event_type
							, result.status
						);
			if (DatabaseReady) {
				try {
					DatabaseAPI.ExecuteNonQuery(sql);
				} catch {
					Altiris.NS.Logging.EventLog.ReportError("Failed to run SQL insert statement:\n\n" + sql);
				}
			} else {
				Console.WriteLine(sql);
			}
			Altiris.NS.Logging.EventLog.ReportVerbose(sql);
		}
		
		private int CreateTable () {
			string sql = @"
if not exists (select 1 from sys.objects where type = 'u' and name = 'CWoC_Pinger_Event')
begin
	create table CWoC_Pinger_Event (
		[timestamp] datetime,
		[resourceguid] uniqueidentifier,
		[hostname] nvarchar(255),
		[eventtype] nvarchar(255),
		[status] nvarchar(max)
	)

	CREATE UNIQUE CLUSTERED INDEX [CWoC_Pinger_Event_ClusteredIndex] ON [dbo].[CWoC_Pinger_Event] 
	(
		[eventtype] ASC,
		[resourceguid] ASC,
		[timestamp] ASC
	)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
end
";
			try {
				DatabaseAPI.ExecuteNonQuery(sql);
				return 0;
			} catch (Exception e) {
	            string msg = string.Format("Caught exception {0}\nInnerException={1}\nStackTrace={2}", e.Message, e.InnerException, e.StackTrace);
				Console.WriteLine(msg);
				EventLog.ReportError(msg);
				return -1;
			}
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
						StoreResult(testresult, "ping");
					} else {
						testresult.status = "0";
						StoreResult(testresult, "ping");	
					}
				} catch (Exception e){
					testresult.status = e.Message;
					StoreResult(testresult, "ping");
				}
			}
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
							testresult.status = sc.Status.ToString();
							StoreResult(testresult, "service_check");
						}
						if (i > 4) {
							string status = String.Format("Failed to start the Altiris Agent service {0} times...", (i + 1).ToString());
							testresult.status = status;
							StoreResult(testresult, "service_check");
						}
					} else {
						testresult.status = sc.Status.ToString();
						StoreResult(testresult, "service_check");
					}
				} catch (Exception e) {
					testresult.status = e.Message;
					StoreResult(testresult, "service_check");
				}
			}
		}
	}

    class Timer {
        private static System.Diagnostics.Stopwatch chrono;

        public static void Init() {
            chrono = new System.Diagnostics.Stopwatch();
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
