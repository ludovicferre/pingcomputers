using System;
using System.Data;
using System.Data.SqlClient;

using Altiris.NS.Logging;
using Altiris.NS.ContextManagement;
using Altiris.NS.Security;

namespace Symantec.CWoC {
    class SecurityAPI {
        public static bool is_user_admin() {
            bool is_altiris_admin = false;
            string identity = string.Empty;

            try {
                SecurityContextManager.SetContextData();
                Role role = SecurityRoleManager.Get(new Guid("{2E1F478A-4986-4223-9D1E-B5920A63AB41}"));
                if (role != null)
                    identity = role.Trustee.Identity;

                if (identity != string.Empty) {
                    foreach (string admin in SecurityTrusteeManager.GetCurrentUserMemberships()) {
                        if (admin == identity) {
                            is_altiris_admin = true;
                            break;
                        }
                    }
                }
            }
            catch {
                is_altiris_admin = false;
            }
            return is_altiris_admin;
        }
    }

    class DatabaseAPI {
        public static DataTable GetTable(string sqlStatement) {
            DataTable t = new DataTable();
            try {
                using (DatabaseContext context = DatabaseContext.GetContext()) {
                    SqlCommand cmdAllResources = context.CreateCommand() as SqlCommand;
                    cmdAllResources.CommandText = sqlStatement;

                    using (SqlDataReader r = cmdAllResources.ExecuteReader()) {
                        t.Load(r);
                    }
                }
                return t;
            }
            catch (Exception e) {
                EventLog.ReportError(String.Format("Error: {0}\nException message = {1}\nStack trace = {2}.\nsqlStatement = {3}", e.Message, e.InnerException, e.StackTrace, sqlStatement));
                throw new Exception("Failed to execute SQL command...");
            }
        }

        public static int ExecuteNonQuery(string sqlStatement) {
            try {
                using (DatabaseContext context = DatabaseContext.GetContext()) {
                    SqlCommand sql_cmd = context.CreateCommand() as SqlCommand;
                    sql_cmd.CommandText = sqlStatement;

                    return sql_cmd.ExecuteNonQuery();
                }
            } catch (Exception e) {
                EventLog.ReportError(String.Format("Error: {0}\nException message = {1}\nStack trace = {2}.\nsqlStatement = {3}", e.Message, e.InnerException, e.StackTrace, sqlStatement));
                throw new Exception("Failed to execute non query SQL command...");
            }

        }

        public static int ExecuteScalar(string sqlStatement) {
            try {
                using (DatabaseContext context = DatabaseContext.GetContext()) {
                    SqlCommand cmd = context.CreateCommand() as SqlCommand;

                    cmd.CommandText = sqlStatement;
                    Object result = cmd.ExecuteScalar();

                    return Convert.ToInt32(result);
                }
            } catch (Exception e) {
                EventLog.ReportError(String.Format("Error: {0}\nException message = {1}\nStack trace = {2}.\nsqlStatement = {3}", e.Message, e.InnerException, e.StackTrace, sqlStatement));
                throw new Exception("Failed to execute scalar SQL command.");
            }
        }
    }

    class QTimer {
        private System.Diagnostics.Stopwatch chrono;
		public string duration {
			get {
				return chrono.ElapsedMilliseconds.ToString();
			}
		}
		
		public string tickcount {
			get {
				return chrono.ElapsedTicks.ToString();
			}
		}
		
		public QTimer() {
			init();
		}

        public void init() {
            chrono = new System.Diagnostics.Stopwatch();
            chrono.Start();
        }

        public void start() {
            chrono.Start();
        }

        public void stop() {
            chrono.Stop();
        }
    }
}
