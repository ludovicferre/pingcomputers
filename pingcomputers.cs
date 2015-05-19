using System;
using System.Data;
using System.Threading;

using Altiris.NS.Logging;
using Altiris.NS.Security;

namespace Symantec.CWoC {
    class PingComputers {
	
		private static readonly string sql = @"
set rowcount {0}
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
   AND dt.LatestInventoryDate < getdate() - {1}
";

		private static string VERSION_MESSAGE = "Welcome to CWoC pinger Version 4.";

		private static string HELP_MESSAGE = "\n" + VERSION_MESSAGE + @". 

This tool retrieves the inactive computers for 7 days from the Symantec CMDB
and checks for each computer whether it is accessible from the network via ICMP
echo request messages (ping).

If a computer is responding to ping, we use a Windows Service Control network 
call to verify the state of the Altiris Agent service. If the service is found
in a Stopped state it is started, else it is left as-is.

Each test result (ping or service control) is logged into the database on the 
'CWoC_pinger_event' table, as well as any exceptions (normally failures to 
resolve a hostname, or to access the remote host service control manager).

Here are the currently supported command line arguments:

    /pingonly
    
        This command line prevent the tool from running the service control
        check on inactive computers.
    
    /days=<n>

        Specify the number of inactive days threshold. By default the value used
        is 7, but if you want to have more aggressive view of the estate you can
        use a lower value, or if you want to restrain the result set you can 
        extend the value to 14, 21 or any number of days that suit your needs.
    
    /test
    
        Limit the count of computers to no more than 500.
    
    /version
    
        Display the version message.
    
    /help || /?
    
        Display this message.
";		
		private static int set_rowcount;
		private static int days_inactive;
		private static bool ping_only;

		public static int Main(string [] args) {
			// Handle command line arguments here
			
			set_rowcount = 0;
			ping_only = false;
			days_inactive = 7;

			if (args.Length > 0) {
				foreach (string arg in args) {
					string _arg = arg.ToLower();
					if (_arg == "/test") {
						set_rowcount = 500;
						continue;
					}
					if (_arg == "/pingonly") {
						ping_only = true;
						continue;
					}
					if (_arg.StartsWith("/days=")) {
						string days = _arg.Replace("/days=", "");
						try {
							days_inactive = Convert.ToInt32(days);
						} catch { }
						continue;
					}
					if (_arg == "/?" || _arg == "/help") {
						Console.WriteLine(HELP_MESSAGE);
						return 0;
					}
					if (_arg == "/version") {
						Console.WriteLine(VERSION_MESSAGE);
						return 0;
					}
					// Invalid command line args result in help message printout
					Console.WriteLine(HELP_MESSAGE);
					return -1;
				}
			}
			
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
				
				string host_list_sql = String.Format(sql, set_rowcount, days_inactive); 
				DataTable computers = DatabaseAPI.GetTable(host_list_sql);
				
				Pinger pinger = new Pinger();
				int _exec_id = pinger.GetExecId();
				pinger.SetExecId(_exec_id);
				
				foreach (DataRow r in computers.Rows) {
					HostData d = new HostData(r[0].ToString(), r[1].ToString());
					pinger.HostQueue.Enqueue(d);
				}

				if (pinger.HostQueue.Count == 0)
					return 0;
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

				if (!ping_only) {
					// Move to stage 2: check the Altiris Agent status if possible
					ServiceChecker sc = new ServiceChecker();
					sc.SetExecId(_exec_id);
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
					}
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
