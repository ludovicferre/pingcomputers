using System;
using System.Collections;
using System.Data;
using System.Threading;
using Altiris.NS.Logging;

namespace Symantec.CWoC {
	class QueueWorker {
		private Queue baseHostQueue;
		public Queue HostQueue;	
		private Queue baseResultQueue;
		public Queue ResultQueue;
	
		public int ThreadPoolDepth;
		public bool DatabaseReady;
		public int currentExecId;

		public QueueWorker(){
			init();
		}
		
		public 	void init() {
			if (CreateTable() == 0)
				DatabaseReady = true;
			else
				DatabaseReady = false;
			
			currentExecId = 0;

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
			string sql = String.Format("insert CWoC_Pinger_Event(_exec_id, timestamp, resourceguid, hostname, eventtype, [status]) values ('{0}', getdate(), '{1}', '{2}', '{3}', '{4}')"
							, currentExecId
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

		public int GetExecId() {
			string sql = @"select isnull(max(_exec_id), -1) + 1 from CWoC_Pinger_Event";
			try {
				return DatabaseAPI.ExecuteScalar(sql);
			} catch (Exception e) {
	            string msg = string.Format("Caught exception {0}\nInnerException={1}\nStackTrace={2}", e.Message, e.InnerException, e.StackTrace);
				Console.WriteLine(msg);
				EventLog.ReportError(msg);
				return -1;
			}
		}
		
		public void SetExecId(int _exec_id) {
			currentExecId = _exec_id;
		}
		
		private int CreateTable () {
			string sql = @"
if not exists (select 1 from sys.objects where type = 'u' and name = 'CWoC_Pinger_Event')
begin
	create table CWoC_Pinger_Event (
		[_exec_id] int not null,
		[timestamp] datetime not null,
		[resourceguid] uniqueidentifier not null,
		[hostname] nvarchar(255) not null,
		[eventtype] nvarchar(255) not null,
		[status] nvarchar(max)
	)

	CREATE UNIQUE CLUSTERED INDEX [CWoC_Pinger_Event_ClusteredIndex] ON [dbo].[CWoC_Pinger_Event] 
	(
		[eventtype] ASC,
		[resourceguid] ASC,
		[timestamp] ASC
	)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]

	CREATE NONCLUSTERED INDEX [CWoC_Pinger_Event_ExecId] ON [dbo].[CWoC_Pinger_Event] 
	(
		[_exec_id] ASC
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
}
