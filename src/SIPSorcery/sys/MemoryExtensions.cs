using System;
using System.Collections.Generic;

namespace SIPSorcery.Sys;

internal static class MemoryExtensions
{
    extension(ReadOnlySpan<char> value)
    {
        public List<string> SplitToList(char separator)
        {
            var result = new List<string>();

            foreach (var token in value.Split(separator))
            {
                result.Add(value[token].ToString());
            }

            return result;
        }
    }

    public static unsafe string ToString(this ReadOnlySpan<byte> buffer, System.Text.Encoding encoding)
    {
        fixed (byte* ptr = buffer)
        {
            return encoding.GetString(ptr, buffer.Length);
        }
    }
}
