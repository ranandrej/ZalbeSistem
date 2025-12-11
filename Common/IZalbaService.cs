using System;
using System.Collections.Generic;
using System.ServiceModel;

namespace Common
{
    [ServiceContract]
    public interface IZalbaService
    {
        [OperationContract]
        bool PosaljiZalbu(byte[] encryptedZalba, byte[] digitalSignature);

        [OperationContract]
        List<string> GetZalbeZaNadzor();

        [OperationContract]
        string TestConnection();

        [OperationContract]
        List<string> PretraziZalbe(string kljucnaRec);

        [OperationContract]
        string GetStatistikaZalbi();
    }
}
