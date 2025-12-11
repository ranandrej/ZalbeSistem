using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.Serialization;

namespace Common.Models
{
    [DataContract]
    public class BannedCertificate
    {
        [DataMember]
        public string SerialNumber { get; set; }

        [DataMember]
        public string Subject { get; set; }

        [DataMember]
        public DateTime BannedDate { get; set; }

        [DataMember]
        public string Reason { get; set; }

        public BannedCertificate()
        {
            BannedDate = DateTime.Now;
        }

        public BannedCertificate(string serialNumber, string subject, string reason) : this()
        {
            SerialNumber = serialNumber;
            Subject = subject;
            Reason = reason;
        }
    }
}