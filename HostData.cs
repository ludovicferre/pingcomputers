using System;

namespace Symantec.CWoC {
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
}
