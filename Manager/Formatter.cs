namespace Manager
{
    public class Formatter
    {
        public static string ParseName(string winLogonName)
        {
            if (string.IsNullOrEmpty(winLogonName))
                return "Unknown";

            string[] parts;

            if (winLogonName.Contains("@"))
            {
                // UPN format
                parts = winLogonName.Split('@');
                return parts[0];
            }
            else if (winLogonName.Contains("\\"))
            {
                // SPN format
                parts = winLogonName.Split('\\');
                return parts[1];
            }
            else
            {
                return winLogonName;
            }
        }
    }
}