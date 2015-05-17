using System;

namespace Symantec.CWoC {	
	class TestResult : HostData {
		public string status;
		
		public TestResult() {
			status = "";
		}
		
		public TestResult(string _status) {
			status = _status;
		}
	}
}
