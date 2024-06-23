using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

class AsyncClient
{
    private const int Port = 5000;
    private const string ServerIp = "127.0.0.1"; 
    private static readonly byte[] key = Encoding.UTF8.GetBytes("ThisIsASecretKey"); 
    private static readonly byte[] iv = Encoding.UTF8.GetBytes("ThisIsAnInitVect"); 

    public static async Task StartClientAsync()
    {
        TcpClient client = new TcpClient();
        await client.ConnectAsync(ServerIp, Port);
        Console.WriteLine("Połączono z serwerem.");
        using (NetworkStream stream = client.GetStream())
        {
            while (true)
            {
                Console.Write("Wpisz wiadomość do wysłania: ");
                string message = Console.ReadLine();
                if (string.IsNullOrEmpty(message))
                    break;
                string encryptedMessage = Encrypt(message);
                Console.WriteLine($"Wysyłanie zaszyfrowane: {encryptedMessage}");
                byte[] data = Encoding.UTF8.GetBytes(encryptedMessage);
                await stream.WriteAsync(data, 0, data.Length);
                byte[] buffer = new byte[1024];
                int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                string encryptedResponse = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                Console.WriteLine($"Otrzymano zaszyfrowane: {encryptedResponse}");
                string response = Decrypt(encryptedResponse);
                Console.WriteLine($"Odpowiedź serwera: {response}");
            }
        }
        client.Close();
        Console.WriteLine("Klient rozłączony.");
    }

    private static string Encrypt(string plainText)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.IV = iv;

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                {
                    swEncrypt.Write(plainText);
                }
                return Convert.ToBase64String(msEncrypt.ToArray());
            }
        }
    }

    private static string Decrypt(string cipherText)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.IV = iv;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(cipherText)))
            using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
            {
                return srDecrypt.ReadToEnd();
            }
        }
    }

    static async Task Main(string[] args)
    {
        await StartClientAsync();
    }
}
