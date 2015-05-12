using System;
using System.Collections.Generic;
using System.Text;
using System.Data;
using System.Data.SqlClient;

using Altiris.Common;
using Altiris.Database;
using Altiris.Database.DataAccessLayer;
using Altiris.NS;
using Altiris.NS.ItemManagement;
using Altiris.NS.Logging;
using Altiris.NS.ContextManagement;
using Altiris.NS.Security;
using Altiris.Resource;

namespace Symantec.CWoC.APIWrappers {
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
				// Console.WriteLine("Running SQL query:\n{0}\n", sqlStatement);
                using (DatabaseContext context = DatabaseContext.GetContext()) {
                    SqlCommand cmdAllResources = context.CreateCommand() as SqlCommand;
                    cmdAllResources.CommandText = sqlStatement;

                    using (SqlDataReader r = cmdAllResources.ExecuteReader()) {
                        t.Load(r);
                    }
                }
				// Console.WriteLine("!!! Returning {0} rows to caller...", t.Rows.Count);
                return t;
            }
            catch (Exception e) {
                Logger.LogEx(e);
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
                Logger.LogEx(e);
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
                Console.WriteLine("Error: {0}\nException message = {1}\nStack trace = {2}.", e.Message, e.InnerException, e.StackTrace);
                throw new Exception("Failed to execute scalar SQL command...");
            }
        }
    }

    class Logger {
        public static void LogEx(Exception e) {
            string msg = string.Format("Caught exception {0}\nInnerException={1}\nStackTrace={2}", e.Message, e.InnerException, e.StackTrace);
            Console.WriteLine(msg);
            EventLog.ReportError(msg);
        }

        public static void Log(string msg) {
            Console.WriteLine(msg);
            EventLog.ReportInfo(msg);
        }

        public static void LogVerbose(string msg) {
            Console.WriteLine(msg);
            EventLog.ReportVerbose(msg);
        }
	}
}
