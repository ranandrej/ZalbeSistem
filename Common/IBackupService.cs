using System;
using System.Collections.Generic;
using System.ServiceModel;

namespace Common
{
    [ServiceContract]
    public interface IBackupService
    {
        [OperationContract]
        void ReplicateZalbe(List<byte[]> encryptedZalbe);

        [OperationContract]
        bool PosaljiZalbu(byte[] encryptedZalba, byte[] digitalSignature);

        [OperationContract]
        List<string> GetZalbeZaNadzor();

        [OperationContract]
        bool IsAvailable();

        [OperationContract]
        string TestConnection();

        [OperationContract]
        List<string> PretraziZalbe(string kljucnaRec);

        [OperationContract]
        string GetStatistikaZalbi();
    }
}
