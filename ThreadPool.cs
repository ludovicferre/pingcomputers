using System;
using System.Collections.ObjectModel;
using System.ServiceProcess;
using System.Threading;

namespace Symantec.CWoC {
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
}

