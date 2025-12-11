using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Common
{
    public interface IZalba
    {
        bool PosaljiZalbuText(string tekst);
        List<string> GetZalbeZaNadzor();
        string TestConnection();
        List<string> PretraziZalbe(string kljucnaRec);
        string GetStatistikaZalbi();
    }
}
