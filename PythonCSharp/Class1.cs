using System;
using System.Diagnostics;
using System.IO.MemoryMappedFiles;

namespace PythonCSharp
{
    public class ToPython
    {
        private readonly string path;
        private readonly MemoryMappedFile file;
        private Process process;

        public ToPython(String path)
        {
            this.path = path;
            this.process = new Process();
            this.process.StartInfo.FileName = "process.exe";
            this.process.StartInfo.Arguments = "-m PySec";
            this.process.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            this.file = MemoryMappedFile.CreateNew("talk",1000, MemoryMappedFileAccess.);
            this.process.Start();

        }

        public dynamic import(String name)
        {

        }
    }
}
