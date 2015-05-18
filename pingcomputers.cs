using System;
using System.Data;
using System.Threading;

using Altiris.NS.Logging;
using Altiris.NS.Security;

namespace Symantec.CWoC {
    class PingComputers {
	
		public static readonly string sql = @"
set rowcount 0
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

		public static int Main() {
			// Handle command line arguments here
			
			// Run the tool
			QTimer main_timer = new QTimer();
			int rc = RunTool();
			main_timer.stop();
			
			Console.WriteLine("Processing completed in {0} ms.", main_timer.duration);

			return rc;
		}
		
		public static int RunTool () {
			int rc = 0;
			try {
				QTimer main_timer = new QTimer();
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
				
				QTimer ping_timer = new QTimer();
				pinger_thread_pool.StartAll(pinger.RunPing);
				pinger_status_thread.Join();
				
				Console.WriteLine("Ping task ran for {0} ms.", ping_timer.duration);
				ping_timer.init();
				pinger_thread_pool.JoinAll();
				Console.WriteLine("Thread convergence took {0} ms.", ping_timer.duration);

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

				QTimer sc_timer = new QTimer();
				sc_thread_pool.StartAll(sc.RunCheck);
				sc_status_thread.Join();
				Console.WriteLine("Done processing service control requests (we had {0} entries) in {1} ms...", sc.ResultQueue.Count.ToString(), sc_timer.duration);
				sc_thread_pool.JoinAll();
				
				Console.WriteLine("Processing of {3} entries completed in {0} ms, using {1} threads for ping and {2} threads for service control checks."
					, main_timer.duration
					, pinger_thread_pool.PoolDepth.ToString()
					, sc_thread_pool.PoolDepth.ToString()
					, computers.Rows.Count.ToString()
					);
				rc = 0;
			} catch (Exception e) {
				EventLog.ReportError(String.Format("{0}\n{1}", e.Message, e.InnerException));
				rc = -1;
			}
			Console.WriteLine("Waiting for thread and process tear down...");		
			return rc;
		}
    }	
}
