using System;
using System.Runtime.Serialization;

namespace Common.Models
{
    [DataContract]
    public class Zalba
    {
        [DataMember]
        public string Id { get; set; }

        [DataMember]
        public string Sadrzaj { get; set; }

        [DataMember]
        public string PosiljaoKorisnik { get; set; }

        [DataMember]
        public DateTime DatumSlanja { get; set; }

        [DataMember]
        public bool NedozvoljenaSadrzaj { get; set; }

        public Zalba()
        {
            Id = Guid.NewGuid().ToString();
            DatumSlanja = DateTime.Now;
            NedozvoljenaSadrzaj = false;
        }

        public Zalba(string sadrzaj, string korisnik) : this()
        {
            Sadrzaj = sadrzaj;
            PosiljaoKorisnik = korisnik;
        }

        public override string ToString()
        {
            return $"[{DatumSlanja:yyyy-MM-dd HH:mm}] {PosiljaoKorisnik}: {Sadrzaj}";
        }
    }
}
