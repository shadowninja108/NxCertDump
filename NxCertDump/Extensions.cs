using System.IO;

namespace NxCertDump
{
    internal static class Extensions
    {
        public static FileInfo GetFile(this DirectoryInfo info, string child)
        {
            return new FileInfo($"{info.FullName}{Path.DirectorySeparatorChar}{child}");
        }

        public static DirectoryInfo GetDirectory(this DirectoryInfo info, string child)
        {
            return new DirectoryInfo($"{info.FullName}{Path.DirectorySeparatorChar}{child}");
        }
    }
}
