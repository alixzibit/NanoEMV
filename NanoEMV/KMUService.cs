// Decompiled with JetBrains decompiler
// Type: HSMapplication.KMUService
// Assembly: KeyManagementService, Version=3.0.0.0, Culture=neutral, PublicKeyToken=null
// MVID: 30EE4B43-3E1E-4A44-8F5A-562B18D99C36
// Assembly location: C:\Users\ali\source\repos\HSMService_MVC_Dhofar_64\HSMService_MVC_Dhofar_64\bin\KeyManagementService.dll

using HSMapplication.Common;
using HSMapplication.Data;
using HSMapplication.DBConn;
using IPKCertificateRequester.Crypto;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Services;
using System.Windows.Forms;

namespace HSMapplication
{
  [WebService(Namespace = "http://tempuri.org/")]
  [WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]
  [ToolboxItem(false)]
  public class KMUService : WebService
  {
    public int counter = 0;
    private static readonly object countLock1 = new object();
    private DBConn_DAL dal = new DBConn_DAL();
    private Utility util = new Utility();
    private string strIpAddress = string.Empty;
    private string responseEx = string.Empty;
    private bool hsmstate = false;
    private string message = string.Empty;
    private LogClass Log_write = new LogClass();
    private string Class_Name = "KMUService.asmx";
    private string Method_Name = string.Empty;
    private AutoResetEvent _blockThread1 = new AutoResetEvent(false);
    private AutoResetEvent _blockThread2 = new AutoResetEvent(true);
    public static ISlot slot = (ISlot) null;
    public static IPkcs11Library pkcs11 = (IPkcs11Library) null;
    public static ISession session = (ISession) null;
    private static int i = 0;
    private static int numThreads = 10;
    private static int ThreadAvailable = 0;
    private static int threadSeekTimeOut = 5000 * KMUService.numThreads;
    private static int TimeOut = 0;
    private static ThreadStart servers;
    private static Thread[] th = new Thread[KMUService.numThreads];
    private static string HSM_USER_NAME = string.Empty;
    private static string HSM_IP = string.Empty;
    private static string HSM_PORT = string.Empty;
    private static string HSMPwd = string.Empty;
    private static string Pkcs11LibraryPath = string.Empty;
    private static string LMK_KEYNAME = string.Empty;
    private static int default_slot = -1;
    private static int MaxSessionAllowed = -1;
    private SingletonHSMClass _SingleInstance = (SingletonHSMClass) null;
    private string path = AppDomain.CurrentDomain.BaseDirectory + "KMULOG_" + DateTime.Now.ToString("yyyyMMdd") + ".txt";
    private static object lockObj = new object();
    private static object rndLock = new object();
    private static Random mrandom = new Random();

    public string Password { get; set; }

    public CKU UserType { get; set; }

    public KMUService()
    {
      this.Method_Name = nameof (KMUService);
      this.GetIP();
      this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Inside KMUService Constructor() without Parameters");
      this._SingleInstance = SingletonHSMClass.GetInstanceHSM();
      KMUService.session = this._SingleInstance.instancename;
    }

    public KMUService(ISession session_Started)
    {
      this.Method_Name = nameof (KMUService);
      this.GetIP();
      this.strIpAddress = SingletonHSMClass.ipAddress;
      this._SingleInstance = SingletonHSMClass.GetInstanceHSM();
      KMUService.session = this._SingleInstance.instancename;
      this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Inside KMUService Constructor and assigning Session Value");
    }

    private static IObjectHandle _findAKeyObject(
      string keyname,
      ISession session = null,
      string key_type = null)
    {
      string str = key_type;
      CKK ckk = str == "AES" ? CKK.CKK_AES : (str == "DES" ? CKK.CKK_DES : (str == "DES2" ? CKK.CKK_DES2 : (str == "DES3" ? CKK.CKK_DES3 : (str == "RSA" ? CKK.CKK_RSA : CKK.CKK_DES2))));
      List<IObjectHandle> allObjects = session.FindAllObjects(new List<IObjectAttribute>()
      {
        SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
        SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
        SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, keyname),
        SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true),
        SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true),
        SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, true),
        SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, true),
        SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, ckk)
      });
      return allObjects.Count > 0 ? allObjects[0] : (IObjectHandle) null;
    }

    [WebMethod]
    public string key_comps(string key, string kcv)
    {
      string empty = string.Empty;
      string str;
      try
      {
        KeyComponents keyComponents = new KeyComponents();
        byte[] byteArray = HelperFunctions.StringToByteArray(key);
        byte[] numArray1 = new byte[byteArray.Length];
        byte[] numArray2 = new byte[byteArray.Length];
        byte[] numArray3 = HelperFunctions.safenetGenRandomBytes(byteArray.Length);
        byte[] a = DESCryptoLib2018.doXor(byteArray, numArray3);
        byte[] numArray4 = new byte[byteArray.Length];
        byte[] numArray5 = HelperFunctions.safenetGenRandomBytes(byteArray.Length);
        byte[] ba = DESCryptoLib2018.doXor(a, numArray5);
        string kcv1 = DESCryptoLib2018.computeKCV(key);
        if (kcv != null && !kcv1.Equals(kcv))
          throw new SystemException("KCV given is not equal with computed KCV!");
        keyComponents.keyFinalKey = key;
        keyComponents.kcvFinalKey = kcv1;
        keyComponents.keyVal1 = HelperFunctions.ByteArrayToString(numArray3);
        keyComponents.kcvKey1 = DESCryptoLib2018.computeKCV(keyComponents.keyVal1);
        keyComponents.keyVal2 = HelperFunctions.ByteArrayToString(numArray5);
        keyComponents.kcvKey2 = DESCryptoLib2018.computeKCV(keyComponents.keyVal2);
        keyComponents.keyVal3 = HelperFunctions.ByteArrayToString(ba);
        keyComponents.kcvKey3 = DESCryptoLib2018.computeKCV(keyComponents.keyVal3);
        keyComponents.keyFinalKey = key;
        keyComponents.kcvFinalKey = kcv;
        str = keyComponents.keyVal1 + ">" + keyComponents.kcvKey1 + "~" + keyComponents.keyVal2 + ">" + keyComponents.kcvKey2 + "~" + keyComponents.keyVal3 + ">" + keyComponents.kcvKey3 + "~" + keyComponents.keyFinalKey + ">" + keyComponents.kcvFinalKey;
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "key components created");
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        str = "Exception [" + ex.Message + " ]";
      }
      return str;
    }

    [WebMethod]
    public string DeleteKey(string Key_Label, string key_type)
    {
      this.Method_Name = nameof (DeleteKey);
      string empty = string.Empty;
      string str;
      try
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Deleting [" + Key_Label + "] Type[" + key_type + "]");
        IObjectHandle akeyObject = KMUService._findAKeyObject(Key_Label, KMUService.session, key_type);
        if (akeyObject == null)
        {
          str = "Unable to Delete Key from HSM";
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Response of Key deletion [" + str + "]");
        }
        else
        {
          KMUService.session.DestroyObject(akeyObject);
          str = "Key Deleted";
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Deleted [" + Key_Label + "] Type[" + key_type + "]");
        }
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        str = "Exception [" + ex.Message + " ]";
      }
      return str;
    }

    [WebMethod]
    public string encrypt_Key(string plainKey, string KEYNAME, bool cbc, string key_type = "DES2")
    {
      string empty = string.Empty;
      string str;
      try
      {
        ++this.counter;
        str = this.Check_Library(plainKey, KEYNAME, cbc, this.counter);
      }
      catch (Exception ex)
      {
        return ex.ToString();
      }
      return str;
    }

    [WebMethod]
    public string encryptKey(string plainKey, string KEYNAME, bool cbc, string key_type = "DES2")
    {
      string empty = string.Empty;
      string str;
      try
      {
        ++this.counter;
        str = this.Check_Library(plainKey, KEYNAME, cbc, this.counter);
      }
      catch (Exception ex)
      {
        str = ex.ToString();
      }
      return str;
    }

    [WebMethod]
    public string GenerateKeyPairReturnClearRSAKey(string lengthInBitsStr, string publicModulus)
    {
      string empty = string.Empty;
      RsaKey returnClearRsaKey = this.doGenerateKeyPairReturnClearRSAKey(lengthInBitsStr, publicModulus);
      this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "-----------------------------------------------------------------------------------------------------------");
      this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "rsa.publicModulus [" + this.util.ByteArrayToString(returnClearRsaKey.publicModulus) + "]");
      this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "rsa.publicExponent [" + this.util.ByteArrayToString(returnClearRsaKey.publicExponent) + "]");
      this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "rsa.privateExponent [" + this.util.ByteArrayToString(returnClearRsaKey.privateExponent) + "]");
      this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "rsa.prime1 [" + this.util.ByteArrayToString(returnClearRsaKey.prime1) + "]");
      this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "rsa.prime2 [" + this.util.ByteArrayToString(returnClearRsaKey.prime2) + "]");
      this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "rsa.exponent1 [" + this.util.ByteArrayToString(returnClearRsaKey.exponent1) + "]");
      this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "rsa.exponent2 [" + this.util.ByteArrayToString(returnClearRsaKey.exponent2) + "]");
      this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "rsa.coefficient [" + this.util.ByteArrayToString(returnClearRsaKey.coefficient) + "]");
      this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "-----------------------------------------------------------------------------------------------------------");
      this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "doGenerateKeyPairReturnClearRSAKey ends");
      this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Sending RSA KeyPair details to Caller");
      return this.util.ByteArrayToString(returnClearRsaKey.publicModulus) + "," + this.util.ByteArrayToString(returnClearRsaKey.publicExponent) + "," + this.util.ByteArrayToString(returnClearRsaKey.privateExponent) + "," + this.util.ByteArrayToString(returnClearRsaKey.prime1) + "," + this.util.ByteArrayToString(returnClearRsaKey.prime2) + "," + this.util.ByteArrayToString(returnClearRsaKey.exponent1) + "," + this.util.ByteArrayToString(returnClearRsaKey.exponent2) + "," + this.util.ByteArrayToString(returnClearRsaKey.coefficient) + "," + this.util.ByteArrayToString(returnClearRsaKey.asn1PubKey) + "," + this.util.ByteArrayToString(returnClearRsaKey.asn1PrivKey);
    }

    [WebMethod]
    public string RSASign(string RSAPubMod, string RSAPubExp, string RSAPriExp, string ClearData)
    {
      this.Method_Name = "doRSASign";
      string empty = string.Empty;
      string str;
      try
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "RSAPubMod [" + RSAPubMod + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "RSAPubExp [" + RSAPubExp + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "RSAPriExp [" + RSAPriExp + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "ClearData [" + ClearData + "]");
        str = HelperFunctions.ByteArrayToString(this.doRSASign(HelperFunctions.StringToByteArray(RSAPubMod), HelperFunctions.StringToByteArray(RSAPubExp), HelperFunctions.StringToByteArray(RSAPriExp), HelperFunctions.StringToByteArray(ClearData)));
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", ex.ToString());
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "HResult [" + ex.HResult.ToString("X") + "]");
        str = "Exception [" + ex.Message + "]";
      }
      return str;
    }

    [WebMethod]
    public string MainCall(string plainKey, string KEYNAME, bool cbc = false)
    {
      object response = (object) null;
      while (true)
      {
        if (KMUService.TimeOut == KMUService.threadSeekTimeOut)
          response = (object) "Thread Exhausted.";
        KMUService.i = 0;
        while (KMUService.i < KMUService.numThreads && KMUService.th[KMUService.i] != null && KMUService.th[KMUService.i].IsAlive)
          ++KMUService.i;
        if (KMUService.i == KMUService.numThreads)
        {
          Thread.Sleep(1000);
          KMUService.TimeOut += 1000;
        }
        else
          break;
      }
      KMUService.TimeOut = 0;
      KMUService.servers = (ThreadStart) (() =>
      {
        Thread.Sleep(100);
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Response of Encrypt method [ " + response?.ToString() + " ]");
      });
      KMUService.th[KMUService.i] = new Thread(KMUService.servers);
      this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Thread Details [ " + this.ShowThreadInformation() + " ]");
      KMUService.th[KMUService.i].Start();
      KMUService.th[KMUService.i].Join();
      Thread.Sleep(500);
      this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Response of Encrypt method afterwards  [ " + response?.ToString() + " ]");
      return response.ToString();
    }

    public void WriteData(string Data)
    {
      if (!System.IO.File.Exists(this.path))
      {
        using (StreamWriter text = System.IO.File.CreateText(this.path))
          text.WriteLine(Data + "\n");
      }
      else
      {
        using (StreamWriter streamWriter = System.IO.File.AppendText(this.path))
          streamWriter.WriteLine(Data);
      }
    }

    [WebMethod]
    public string GetLMK()
    {
      this.Method_Name = nameof (GetLMK);
      string empty = string.Empty;
      try
      {
        if (this._SingleInstance == null)
          return "Unable to Generate Session";
        if ((uint) this._SingleInstance.counter <= 0U)
          return "NA";
        IObjectHandle akeyObject = KMUService.findAKeyObject(KMUService.LMK_KEYNAME);
        if (Convert.ToInt32(akeyObject.ToString()) <= 0)
          return "NA";
        byte[] data = new byte[8];
        IMechanism mechanism = SingletonHSMClass.factories.MechanismFactory.Create(CKM.CKM_DES3_ECB);
        return HelperFunctions.ByteArrayToString(KMUService.session.Encrypt(mechanism, akeyObject, data)).Substring(0, 6);
      }
      catch (NullReferenceException ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        return ex.ToString();
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        return ex.ToString();
      }
    }

    [WebMethod]
    public string GetClearComponent(string KeyName)
    {
      string empty = string.Empty;
      string message;
      try
      {
        IObjectHandle akeyObject = KMUService.findAKeyObject(KeyName);
        byte[] encryptedData = KMUService.session.WrapKey(KMUService.session.Factories.MechanismFactory.Create(CKM.CKM_DES3_CBC), akeyObject, akeyObject);
        message = this.util.ByteArrayToString(KMUService.session.Decrypt(KMUService.session.Factories.MechanismFactory.Create(CKM.CKM_DES3_CBC), akeyObject, encryptedData));
        this.Log_write.LogWrite(this.GetIP(), this.Class_Name, nameof (GetClearComponent), "Information", "Key  [" + message + "]");
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.GetIP(), this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.GetIP(), this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.GetIP(), this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        message = ex.Message;
      }
      return message;
    }

    public string getLMKKCV()
    {
      try
      {
        string lmkKeyname = KMUService.LMK_KEYNAME;
        this._SingleInstance = SingletonHSMClass.GetInstanceHSM();
        KMUService.session = this._SingleInstance.instancename;
        IObjectHandle akeyObject = KMUService.findAKeyObject(lmkKeyname);
        byte[] data = new byte[8];
        IMechanism mechanism = SingletonHSMClass.factories.MechanismFactory.Create(CKM.CKM_DES3_ECB);
        byte[] ba = KMUService.session.Encrypt(mechanism, akeyObject, data);
        SingletonHSMClass.HSMLogout(KMUService.session);
        return HelperFunctions.ByteArrayToString(ba).Substring(0, 6);
      }
      catch (Exception ex)
      {
        throw;
      }
    }

    [WebMethod]
    public bool CheckLogin()
    {
      this.Method_Name = nameof (CheckLogin);
      bool flag1 = false;
      int counter = this._SingleInstance.counter;
      bool flag2;
      try
      {
        flag1 = true;
        return this._SingleInstance.counter > 0;
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        flag2 = false;
      }
      return flag2;
    }

    public string ShowThreadInformation()
    {
      string str = (string) null;
      Thread currentThread = Thread.CurrentThread;
      lock (KMUService.lockObj)
        str = string.Format(" Background: {0}", (object) currentThread.IsBackground) + string.Format(" and   Thread Pool: {0}", (object) currentThread.IsThreadPoolThread) + string.Format(" and   Thread ID: {0}", (object) currentThread.ManagedThreadId);
      return str;
    }

    [WebMethod]
    public string GetIP()
    {
      string hostName = Dns.GetHostName();
      IPAddress[] addressList = Dns.GetHostEntry(hostName).AddressList;
      this.strIpAddress = addressList[addressList.Length - 1].ToString();
      return this.strIpAddress + " - " + hostName;
    }

    public string encryptKey(string plainKey, string KEYNAME)
    {
      ++this.counter;
      return this.Check_Library(plainKey, KEYNAME, counter: this.counter);
    }

    public string tDesEncrypt(string Key, string Data, string CMode, bool Decrypt = false)
    {
      try
      {
        this.Method_Name = "TDesEncrypt";
        Utility utility = new Utility();
        TripleDESCryptoServiceProvider cryptoServiceProvider = new TripleDESCryptoServiceProvider();
        cryptoServiceProvider.Key = utility.StringToByteArray(Key);
        if (CMode == "ECB")
          cryptoServiceProvider.Mode = CipherMode.ECB;
        else if (CMode == "CBC")
          cryptoServiceProvider.Mode = CipherMode.CBC;
        else if (CMode == "CFB")
          cryptoServiceProvider.Mode = CipherMode.CFB;
        else if (CMode == "CTS")
          cryptoServiceProvider.Mode = CipherMode.CTS;
        else if (CMode == "OFB")
          cryptoServiceProvider.Mode = CipherMode.OFB;
        cryptoServiceProvider.Padding = PaddingMode.None;
        cryptoServiceProvider.IV = utility.StringToByteArray("0000000000000000");
        ICryptoTransform transform = Decrypt ? cryptoServiceProvider.CreateDecryptor() : cryptoServiceProvider.CreateEncryptor();
        byte[] byteArray = utility.StringToByteArray(Data);
        MemoryStream memoryStream = new MemoryStream(utility.StringToByteArray(Data));
        CryptoStream cryptoStream = new CryptoStream((Stream) memoryStream, transform, CryptoStreamMode.Write);
        cryptoStream.Write(byteArray, 0, byteArray.Length);
        cryptoStream.FlushFinalBlock();
        return utility.ByteArrayToString(memoryStream.ToArray());
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        return ex.Message;
      }
    }

    private static IObjectHandle findAKeyObject(string LMK_keyname)
    {
      List<IObjectHandle> objectHandleList = new List<IObjectHandle>();
      try
      {
        List<IObjectAttribute> objectAttributeList = new List<IObjectAttribute>();
        if (KMUService.session != null)
        {
          List<IObjectAttribute> attributes = new List<IObjectAttribute>()
          {
            KMUService.session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
            KMUService.session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, LMK_keyname),
            KMUService.session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY)
          };
          if (LMK_keyname.ToLower().Contains("lmk"))
          {
            attributes.Add(KMUService.session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_DES3));
            attributes.Add(KMUService.session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true));
          }
          attributes.Add(KMUService.session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true));
          attributes.Add(KMUService.session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true));
          attributes.Add(KMUService.session.Factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, true));
          attributes.Add(KMUService.session.Factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, true));
          objectHandleList = KMUService.session.FindAllObjects(attributes);
        }
      }
      catch (Exception ex)
      {
        throw;
      }
      return objectHandleList.Count > 0 ? objectHandleList[0] : (IObjectHandle) null;
    }

    [WebMethod]
    public string findAllKeys()
    {
      string str1 = string.Empty;
      try
      {
        string str2 = string.Empty;
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Started find All Keys Methods");
        new List<IObjectAttribute>()
        {
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true)
        };
        List<IObjectHandle> allObjects = KMUService.session.FindAllObjects((List<IObjectAttribute>) null);
        int num1 = 0;
        List<KMUService.KeyData> keyDataList = new List<KMUService.KeyData>();
        foreach (IObjectHandle objHandle in allObjects)
        {
          KMUService.KeyData keyData = new KMUService.KeyData();
          keyData.index = num1;
          keyData.KeyType = "Unknown";
          keyData.Keyname = "No Name";
          ++num1;
          foreach (IObjectAttribute attribute in this.GetAttributeList(objHandle, new List<CKA>()
          {
            CKA.CKA_LABEL,
            CKA.CKA_KEY_TYPE,
            CKA.CKA_KEY_GEN_MECHANISM,
            CKA.CKA_CHECK_VALUE
          }))
          {
            ulong num2 = attribute.Type;
            CKA result1;
            if (System.Enum.TryParse<CKA>(num2.ToString(), out result1))
            {
              string str3 = this.util.ConvertHexToString(this.util.ByteArrayToString(attribute.GetValueAsByteArray()));
              string str4 = result1.ToString();
              if (!(str4 == "CKA_LABEL"))
              {
                if (str4 == "CKA_KEY_TYPE")
                {
                  num2 = attribute.GetValueAsUlong();
                  CKK result2;
                  if (System.Enum.TryParse<CKK>(num2.ToString(), out result2))
                  {
                    keyData.KeyType = result2.ToString();
                    str1 += string.Format("{0}~", (object) result2.ToString().Replace("\0", "").Replace("\n", "").Replace("\r", "").Trim());
                  }
                }
              }
              else
              {
                keyData.Keyname = str3;
                str1 += string.Format("{0}^", (object) str3.Replace("\0", "").Replace("\n", "").Replace("\r", "").Trim());
              }
            }
          }
          keyDataList.Add(keyData);
          str2 = string.Format("{0} : {1}", (object) num1, (object) str1);
        }
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Keys  [" + str1 + "]");
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        str1 = ex.Message;
      }
      return str1;
    }

    [WebMethod]
    public string doGenerateLMKReturnClearKey(string KeyName, string Key_type)
    {
      this.Method_Name = nameof (doGenerateLMKReturnClearKey);
      string empty = string.Empty;
      try
      {
        CKK ckk;
        CKM type;
        if (Key_type == "DES3")
        {
          ckk = CKK.CKK_DES3;
          type = CKM.CKM_DES3_KEY_GEN;
        }
        else
        {
          ckk = CKK.CKK_DES2;
          type = CKM.CKM_DES2_KEY_GEN;
        }
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Creating LMK");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "LMK Name [" + KeyName + "] Mechanism[" + Key_type + "]");
        if (KMUService.session == null)
          this.uninitialize();
        List<IObjectAttribute> attributes = new List<IObjectAttribute>();
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, KeyName));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, true));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, true));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, ckk));
        IMechanism mechanism1 = SingletonHSMClass.factories.MechanismFactory.Create(type);
        IObjectHandle key1 = KMUService.session.GenerateKey(mechanism1, attributes);
        byte[] data = new byte[8];
        IMechanism mechanism2 = SingletonHSMClass.factories.MechanismFactory.Create(CKM.CKM_DES3_ECB);
        byte[] ba = KMUService.session.Encrypt(mechanism2, key1, data);
        IObjectHandle key2 = KMUService.session.GenerateKey(mechanism1, new List<IObjectAttribute>()
        {
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, false),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, ckk),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, true)
        });
        byte[] encryptedData = KMUService.session.WrapKey(mechanism2, key2, key1);
        if (encryptedData == null)
        {
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "wrappedKeyBytes == null");
          KMUService.session.Logout();
          return (string) null;
        }
        string[] strArray = new string[2]
        {
          HelperFunctions.ByteArrayToString(KMUService.session.Decrypt(mechanism2, key2, encryptedData)),
          HelperFunctions.ByteArrayToString(ba).Substring(0, 6)
        };
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "LMK Name [" + KeyName + "] Mechanism[" + Key_type + "] KCV [" + strArray[1] + "]");
        KMUService.session.DestroyObject(key2);
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Deleting [" + KeyName + "]");
        this.DeleteKey(KeyName, Key_type);
        return this.key_comps(strArray[0], strArray[1]);
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        return (string) null;
      }
    }

    public IObjectHandle createLMKKeyFrom3Components(
      string plainKeyValue,
      string keyKCV)
    {
      this.Method_Name = nameof (createLMKKeyFrom3Components);
      IObjectHandle keyHandle = (IObjectHandle) null;
      try
      {
        byte[] byteArray1 = HelperFunctions.StringToByteArray(plainKeyValue);
        CKK ckk;
        CKM type;
        if (plainKeyValue.Length == 48)
        {
          ckk = CKK.CKK_DES3;
          type = CKM.CKM_DES3_ECB;
        }
        else if (plainKeyValue.Length == 32)
        {
          ckk = CKK.CKK_DES2;
          type = CKM.CKM_DES3_ECB;
        }
        else if (plainKeyValue.Length == 16)
        {
          ckk = CKK.CKK_DES;
          type = CKM.CKM_DES_ECB;
        }
        else
        {
          KMUService.session.Logout();
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Fail creating key object, key must be ODD value");
          return (IObjectHandle) null;
        }
        keyHandle = KMUService.session.CreateObject(new List<IObjectAttribute>()
        {
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, ckk),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "LMK_MASTER_KEY"),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, true),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, true),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, false),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE, byteArray1)
        });
        if (keyHandle == null)
        {
          KMUService.session.Logout();
          return (IObjectHandle) null;
        }
        IMechanism mechanism = SingletonHSMClass.factories.MechanismFactory.Create(type);
        if (!string.IsNullOrEmpty(keyKCV))
        {
          byte[] data = new byte[8];
          byte[] numArray = KMUService.session.Encrypt(mechanism, keyHandle, data);
          byte[] byteArray2 = HelperFunctions.StringToByteArray(keyKCV);
          for (int index = 0; index < byteArray2.Length; ++index)
          {
            if ((int) numArray[index] != (int) byteArray2[index])
            {
              KMUService.session.Logout();
              return (IObjectHandle) null;
            }
          }
        }
        KMUService.session.Logout();
        return keyHandle;
      }
      catch (Exception ex)
      {
      }
      KMUService.session.Logout();
      return keyHandle;
    }

    [WebMethod]
    public string[] doGenerateKeyPairReturnClear(string lengthInBitsStr, string publicModulus)
    {
      byte[] byteArray = HelperFunctions.StringToByteArray(publicModulus);
      ulong uint32 = (ulong) Convert.ToUInt32(lengthInBitsStr);
      this.Method_Name = nameof (doGenerateKeyPairReturnClear);
      byte[] random = KMUService.session.GenerateRandom(20);
      List<IObjectAttribute> publicKeyAttributes = new List<IObjectAttribute>();
      publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, false));
      publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false));
      publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, SingletonHSMClass.ApplicationName));
      publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_ID, random));
      publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true));
      publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, true));
      publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY_RECOVER, true));
      publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, true));
      publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS_BITS, uint32));
      publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_PUBLIC_EXPONENT, byteArray));
      List<IObjectAttribute> privateKeyAttributes = new List<IObjectAttribute>();
      privateKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, false));
      privateKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true));
      privateKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, SingletonHSMClass.ApplicationName));
      privateKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_ID, random));
      privateKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, true));
      privateKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true));
      privateKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, true));
      privateKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN_RECOVER, true));
      privateKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, true));
      IMechanism mechanism1 = SingletonHSMClass.factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
      IObjectHandle publicKeyHandle = (IObjectHandle) null;
      IObjectHandle privateKeyHandle = (IObjectHandle) null;
      KMUService.session.GenerateKeyPair(mechanism1, publicKeyAttributes, privateKeyAttributes, out publicKeyHandle, out privateKeyHandle);
      IMechanism mechanism2 = SingletonHSMClass.factories.MechanismFactory.Create(CKM.CKM_DES3_KEY_GEN);
      IMechanism mechanism3 = SingletonHSMClass.factories.MechanismFactory.Create(CKM.CKM_DES3_ECB);
      IObjectHandle key = KMUService.session.GenerateKey(mechanism2, new List<IObjectAttribute>()
      {
        SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, false),
        SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
        SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_DES3),
        SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true),
        SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, true)
      });
      byte[] encryptedData1 = KMUService.session.WrapKey(mechanism3, key, publicKeyHandle);
      byte[] encryptedData2 = KMUService.session.WrapKey(mechanism3, key, privateKeyHandle);
      if (encryptedData1 == null || encryptedData2 == null)
      {
        KMUService.session.Logout();
        return (string[]) null;
      }
      byte[] ba1 = KMUService.session.Decrypt(mechanism3, key, encryptedData1);
      byte[] ba2 = KMUService.session.Decrypt(mechanism3, key, encryptedData2);
      KMUService.session.DestroyObject(key);
      KMUService.session.DestroyObject(publicKeyHandle);
      KMUService.session.DestroyObject(privateKeyHandle);
      KMUService.session.Logout();
      return new string[2]
      {
        HelperFunctions.ByteArrayToString(ba1),
        HelperFunctions.ByteArrayToString(ba2)
      };
    }

    [WebMethod]
    public string MasterKeyDerivationNormalPan(
      string name,
      string pan,
      string panSeq,
      string keyName)
    {
      try
      {
        this.Method_Name = nameof (MasterKeyDerivationNormalPan);
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Name [ " + name + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Pan [ " + pan.Substring(0, 6) + "XXXXXX" + pan.Substring(12) + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Pan Sequence [ " + panSeq + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "KeyName [ " + keyName + "]");
        if (panSeq.Length > 2)
        {
          panSeq = panSeq.Substring(panSeq.Length - 2);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Updated Pan Sequence [ " + panSeq + "]");
        }
        Utility utility = new Utility();
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", this.Method_Name);
        string hex = pan.Substring(pan.Length - 14) + panSeq;
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "pan.Substring(pan.Length - 14) + panSeq");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Left Part  [ " + hex.Substring(0, 4) + "XXXXXX" + hex.Substring(12) + "]");
        string input1 = utility.ByteArrayToString(utility.buildKey(utility.StringToByteArray(hex), utility.StringToByteArray("FFFFFFFFFFFFFFFF")));
        string input2 = pan.Substring(pan.Length - 14) + panSeq;
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Input Right [ " + input1 + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Input  Left [ " + input2 + "]");
        ASCIIEncoding asciiEncoding = new ASCIIEncoding();
        string str;
        if (name.EndsWith("_A"))
        {
          str = this.generateKeyFromHsm(input2, keyName);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "name : [" + name + "] Key : [" + str + "]");
        }
        else if (name.EndsWith("_B"))
        {
          str = this.generateKeyFromHsm(input1, keyName);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "name Key : [" + str + "]");
        }
        else
        {
          str = this.generateKeyFromHsm(input2, keyName) + this.generateKeyFromHsm(input1, keyName);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "name : [" + name + "] Key : [" + str + "]");
        }
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", name + " FinalKey [ " + str + " ]");
        if (name.StartsWith("KCV"))
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", name + " FinalKey KCV [ " + str + " ]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Final Key Responding to application : [" + str + "]");
        return str;
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        return ex.Message;
      }
    }

    public string MasterKeyDerivationNormalPan(
      string name,
      string pan,
      string panSeq,
      string keyName,
      string skudek)
    {
      try
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Name [ " + name + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Pan [ " + pan.Substring(0, 6) + "XXXXXX" + pan.Substring(12) + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Pan Sequence [" + panSeq + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "KeyName [" + keyName + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "SKU Dek [" + skudek + "]");
        Utility utility = new Utility();
        this.Method_Name = nameof (MasterKeyDerivationNormalPan);
        string empty = string.Empty;
        string str1 = pan.Substring(pan.Length - 14) + panSeq;
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "pan.Substring(pan.Length - 14) + panSeq");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Left Part  [ " + str1.Substring(0, 4) + "XXXXXX" + str1.Substring(10) + "]");
        string str2 = utility.ByteArrayToString(utility.buildKey(utility.StringToByteArray(str1), utility.StringToByteArray("FFFFFFFFFFFFFFFF")));
        string str3 = pan.Substring(pan.Length - 14) + panSeq;
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Input Right [" + str2 + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Input  Left [" + str3 + "]");
        ASCIIEncoding asciiEncoding = new ASCIIEncoding();
        string str4;
        if (name.EndsWith("_B"))
        {
          str4 = this.generateKeyFromHsm(str2.Substring(0, str2.Length / 2), keyName);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "name Key : [" + str4 + "]");
        }
        else if (name.EndsWith("_A"))
        {
          str4 = this.generateKeyFromHsm(str3.Substring(0, str3.Length / 2), keyName);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "name Key : [" + str4 + "]");
        }
        else
        {
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Name Doesnot Contains A and B");
          string keyFromHsm = this.generateKeyFromHsm(str1, keyName);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Final Key to be encrypt with skudek[" + keyFromHsm + "]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "skudek to encrypt  Final Key[" + skudek + "]");
          string str5 = this.tDesEncrypt(skudek, keyFromHsm, "ECB");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Encypted Key sent to Communicator[" + str5 + "]");
          str4 = str5;
        }
        return str4;
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        return ex.Message;
      }
    }

    [WebMethod]
    public string MasterKeYDerivationLongPan(
      string name,
      string pan,
      string panSeqNo,
      string keyName)
    {
      Utility utility = new Utility();
      string strInput = pan + panSeqNo;
      byte[] numArray = new byte[32];
      byte[] bytes = utility.String_To_Bytes(strInput);
      this.Method_Name = "MasterKeyDerivationLongPan";
      byte[] hash = new SHA1CryptoServiceProvider().ComputeHash(bytes);
      string s = utility.ByteArrayToString(hash);
      string first16DecofString = utility.getFirst16DecofString(s);
      string str1 = utility.ByteArrayToString(utility.buildKey(utility.StringToByteArray(first16DecofString), utility.StringToByteArray("FFFFFFFFFFFFFFFF")));
      string str2 = first16DecofString;
      ASCIIEncoding asciiEncoding = new ASCIIEncoding();
      string str3 = !name.EndsWith("_B") ? (!name.EndsWith("_A") ? this.generateKeyFromHsm(first16DecofString, keyName) : this.generateKeyFromHsm(str2.Substring(0, str2.Length / 2 - 1), keyName)) : this.generateKeyFromHsm(str1.Substring(0, str1.Length / 2), keyName);
      this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Key [ " + str3 + " ]");
      return str3;
    }

    public byte[] ipkvalues(byte[] ipkvalues_data)
    {
      this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", Encoding.ASCII.GetString(ipkvalues_data));
      this.Method_Name = "IPK Values";
      return ipkvalues_data;
    }

    public string generateKeyFromHsm(string input, string keyName)
    {
      this.Method_Name = nameof (generateKeyFromHsm);
      Utility utility = new Utility();
      try
      {
        string key = this.encryptKey(input, keyName);
        return utility.GetOddParityDESKEY(key);
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        return ex.Message;
      }
    }

    public static string RandomString(int length) => new string(Enumerable.Repeat<string>("ABCDEF0123456789", length).Select<string, char>((Func<string, char>) (s => s[KMUService.mrandom.Next(s.Length)])).ToArray<char>());

    [WebMethod]
    public int CreateIPKRequestMCHIPhIP(string IpkId, string len)
    {
      this.Method_Name = nameof (CreateIPKRequestMCHIPhIP);
      string publicModulus = "03";
      try
      {
        bool flag = true;
        int num1 = -1;
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Generating  RSA pair for IPK[ " + IpkId + " ] and Length [ " + len + " ]");
        RsaKey returnClearRsaKey = this.doGenerateKeyPairReturnClearRSAKey(len, publicModulus);
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", " RSA pair Generated successfully for IPK[ " + IpkId + " ] and Length [ " + len + " ]");
        if (flag)
        {
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Storing RSA key pair in DB for IPK[ " + IpkId + " ] and Length [ " + len + " ]");
          num1 = this.dal.Insert_RSA_KeyPair(this.util.ByteArrayToString(returnClearRsaKey.publicModulus), this.util.ByteArrayToString(returnClearRsaKey.publicExponent), this.util.ByteArrayToString(returnClearRsaKey.privateExponent), this.util.ByteArrayToString(returnClearRsaKey.prime1), this.util.ByteArrayToString(returnClearRsaKey.prime2), this.util.ByteArrayToString(returnClearRsaKey.exponent1), this.util.ByteArrayToString(returnClearRsaKey.exponent2), this.util.ByteArrayToString(returnClearRsaKey.coefficient), this.util.ByteArrayToString(returnClearRsaKey.asn1PrivKey), this.util.ByteArrayToString(returnClearRsaKey.asn1PubKey), IpkId, len);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Result of Storing RSA key pair for IPK[ " + IpkId + " ] and Length [ " + len + " ] Result[ " + num1.ToString() + " ]");
        }
        if (num1 == -1)
        {
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Unable to Insert RSA key pair for IPK[ " + IpkId + " ] and Length [ " + len + " ] Result[ " + num1.ToString() + " ]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Exiting Method");
          return num1;
        }
        int num2 = Convert.ToInt32(len) / 8;
        string str1 = string.Format("{0:X}", (object) num2);
        string str2 = "01";
        string str3 = "";
        string str4 = "";
        string str5 = "";
        string str6 = string.Empty;
        string str7 = "01";
        string str8 = "01";
        string str9 = "6A";
        string str10 = "11";
        string empty = string.Empty;
        string trackingnumber = KMUService.RandomString(6);
        string str11 = trackingnumber;
        DataTable dataTable1 = new DataTable();
        int num3 = -1;
        DataTable dataTable2 = this.dal.Read_IPK_Details(IpkId);
        if (dataTable2.Rows.Count > 0)
        {
          str5 = dataTable2.Rows[0]["BIN"].ToString().Trim() + "FF";
          str6 = dataTable2.Rows[0]["EXPIRY"].ToString().Trim();
          str4 = dataTable2.Rows[0]["SERVICE_IDENTIFIER"].ToString().Trim();
          str3 = dataTable2.Rows[0]["IPK_EXPO"].ToString().Trim();
          str2 = dataTable2.Rows[0]["IPK_EXPO_LEN"].ToString().Trim();
        }
        string hex1 = this.util.ByteArrayToString(returnClearRsaKey.publicModulus);
        string hex2 = this.util.ByteArrayToString(returnClearRsaKey.publicExponent);
        string hex3 = this.util.ByteArrayToString(returnClearRsaKey.privateExponent);
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "RS_PUB_MOD:" + hex1);
        string strInput1 = str5 + trackingnumber + hex1 + str3;
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "unsigned_ipkRequest:" + strInput1);
        byte[] numArray1 = new byte[32];
        byte[] bytes1 = this.util.String_To_Bytes(strInput1);
        SHA1 shA1 = (SHA1) new SHA1CryptoServiceProvider();
        string str12 = this.util.ByteArrayToString(shA1.ComputeHash(bytes1));
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "hash :" + str12);
        string HipData = str5 + trackingnumber + str8 + str12;
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "PreparedDataHip : " + HipData);
        string str13 = str5 + trackingnumber + str8 + str1 + str2 + hex1 + publicModulus;
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "RS_PUB_EXP:" + hex2);
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "RS_PRI_EXP:" + hex3);
        int num4 = 36;
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "lengthString Static  :" + num4.ToString());
        int length = Convert.ToInt32(num2 - num4) * 2;
        string str14 = hex1.Substring(0, length);
        string str15 = str13;
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Part1 :" + str13);
        string str16 = str9 + str10 + str5 + str6 + str11 + str7 + str8 + str1 + str2 + str14;
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Part2 :" + str16);
        string strInput2 = str10 + str5 + str6 + str11 + str7 + str8 + str1 + str2 + hex1 + publicModulus;
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Part3 :" + strInput2);
        byte[] numArray2 = new byte[32];
        byte[] bytes2 = this.util.String_To_Bytes(strInput2);
        string Hash_Data = this.util.ByteArrayToString(shA1.ComputeHash(bytes2));
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "hashP3 :" + Hash_Data);
        string str17 = "BC";
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Part4 :" + str17);
        byte[] byteArray = HelperFunctions.StringToByteArray(str16 + Hash_Data + str17);
        string encryptedData = HelperFunctions.ByteArrayToString(this.doRSASign(HelperFunctions.StringToByteArray(hex1), HelperFunctions.StringToByteArray(hex2), HelperFunctions.StringToByteArray(hex3), byteArray));
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Combine and Encrypted of Part 2,3,4 :" + encryptedData);
        string SipData = str15 + encryptedData;
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "FINAL PART:" + SipData);
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "FILE UPDATED ");
        string strInput3 = HelperFunctions.ByteArrayToString(this.PublicDecryption(encryptedData, HelperFunctions.ByteArrayToString(returnClearRsaKey.publicExponent), HelperFunctions.ByteArrayToString(returnClearRsaKey.publicModulus))).Substring(2, 28) + HelperFunctions.ByteArrayToString(returnClearRsaKey.publicModulus) + HelperFunctions.ByteArrayToString(returnClearRsaKey.publicExponent);
        string str18 = this.util.ByteArrayToString(shA1.ComputeHash(this.util.String_To_Bytes(strInput3)));
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", Hash_Data + "==" + str18);
        if (Hash_Data == str18)
        {
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Hash Validate Successfully");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", strInput1 + encryptedData);
          num3 = this.dal.Update_IPK_DetailsMCHIP(IpkId, Hash_Data, SipData, HipData, trackingnumber);
        }
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Part 1,2,3,4 :" + num3.ToString());
        return num3;
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        return -1;
      }
    }

    [WebMethod]
    public int CreateIPKRequest(string IpkId, string len)
    {
      string publicModulus = "03";
      this.Method_Name = nameof (CreateIPKRequest);
      int num1 = -1;
      try
      {
        bool flag = true;
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Generating  RSA pair for IPK[ " + IpkId + " ] and Length [ " + len + " ]");
        RsaKey returnClearRsaKey = this.doGenerateKeyPairReturnClearRSAKey(len, publicModulus);
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", " RSA pair Generated successfully for IPK[ " + IpkId + " ] and Length [ " + len + " ]");
        if (flag)
        {
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Storing RSA key pair in DB for IPK[ " + IpkId + " ] and Length [ " + len + " ]");
          num1 = this.dal.Insert_RSA_KeyPair(this.util.ByteArrayToString(returnClearRsaKey.publicModulus), this.util.ByteArrayToString(returnClearRsaKey.publicExponent), this.util.ByteArrayToString(returnClearRsaKey.privateExponent), this.util.ByteArrayToString(returnClearRsaKey.prime1), this.util.ByteArrayToString(returnClearRsaKey.prime2), this.util.ByteArrayToString(returnClearRsaKey.exponent1), this.util.ByteArrayToString(returnClearRsaKey.exponent2), this.util.ByteArrayToString(returnClearRsaKey.coefficient), this.util.ByteArrayToString(returnClearRsaKey.asn1PubKey), this.util.ByteArrayToString(returnClearRsaKey.asn1PrivKey), IpkId, len);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Result of Storing RSA key pair for IPK[ " + IpkId + " ] and Length [ " + len + " ] Result[ " + num1.ToString() + " ]");
        }
        if (num1 == -1)
        {
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Unable to Insert RSA key pair for IPK[ " + IpkId + " ] and Length [ " + len + " ] Result[ " + num1.ToString() + " ]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Exiting Method");
          return num1;
        }
        int num2 = Convert.ToInt32(len) / 8;
        string str1 = string.Format("{0:X}", (object) num2);
        string str2 = "01";
        string str3 = "";
        string str4 = "";
        string trackingnumber = "";
        string str5 = "";
        string str6 = string.Empty;
        string str7 = "01";
        string str8 = "01";
        string str9 = "22";
        string str10 = "23";
        string str11 = "02";
        int num3 = 20;
        string str12 = "0000";
        string empty = string.Empty;
        int num4 = -1;
        DataTable dataTable1 = new DataTable();
        DataTable dataTable2 = this.dal.Read_IPK_Details(IpkId);
        if (dataTable2.Rows.Count > 0)
        {
          str5 = dataTable2.Rows[0]["BIN"].ToString().Trim();
          trackingnumber = dataTable2.Rows[0]["TRACKING_NUMBER"].ToString().Trim();
          str6 = dataTable2.Rows[0]["EXPIRY"].ToString().Trim();
          str4 = dataTable2.Rows[0]["SERVICE_IDENTIFIER"].ToString().Trim();
          str3 = dataTable2.Rows[0]["IPK_EXPO"].ToString().Trim();
          str2 = dataTable2.Rows[0]["IPK_EXPO_LEN"].ToString().Trim();
        }
        string hex1 = this.util.ByteArrayToString(returnClearRsaKey.publicModulus);
        string hex2 = this.util.ByteArrayToString(returnClearRsaKey.publicExponent);
        string hex3 = this.util.ByteArrayToString(returnClearRsaKey.privateExponent);
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "RS_PUB_MOD [ " + hex1 + " ]");
        string str13 = str9 + str1 + hex1 + str2 + str3 + trackingnumber;
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "unsigned_ipkRequest [ " + str13 + " ]");
        int num5 = (str10 + str4 + str12 + str11 + str5 + "FF" + str6 + trackingnumber + str7 + str8 + str1 + str2 + str3).Length / 2 + num3;
        int length = Convert.ToInt32(num2 - num5) * 2;
        string str14 = hex1.Substring(0, length);
        string strInput = str10 + str4 + str12 + str11 + str5 + "FF" + str6 + trackingnumber + str7 + str8 + str1 + str2 + str14 + str3;
        byte[] numArray = new byte[32];
        string str15 = this.util.ByteArrayToString(new SHA1CryptoServiceProvider().ComputeHash(this.util.String_To_Bytes(strInput)));
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Hash [ " + str15 + " ]");
        string hex4 = strInput + str15;
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "self_signed_Ipk_Req [ " + hex4 + " ]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "RS_PUB_EXP [ " + hex2 + " ]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "RS_PRI_EXP [ " + hex3 + " ]");
        byte[] byteArray = HelperFunctions.StringToByteArray(hex4);
        string encryptedData = HelperFunctions.ByteArrayToString(this.doRSASign(HelperFunctions.StringToByteArray(hex1), HelperFunctions.StringToByteArray(hex2), HelperFunctions.StringToByteArray(hex3), byteArray));
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", " signedData [ " + encryptedData + " ]");
        string str16 = HelperFunctions.ByteArrayToString(this.PublicDecryption(encryptedData, HelperFunctions.ByteArrayToString(returnClearRsaKey.publicExponent), HelperFunctions.ByteArrayToString(returnClearRsaKey.publicModulus)));
        if (str15 == str16.Substring(str16.Length - 40))
        {
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Hash Validate Successfully");
          num4 = this.dal.Update_IPK_DetailsMCHIP(IpkId, str15, str13 + encryptedData, str15, trackingnumber);
        }
        return num4;
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        return -1;
      }
    }

    [WebMethod]
    public int CreateLicense(string IpkId, string len)
    {
      string publicModulus = "03";
      this.Method_Name = nameof (CreateLicense);
      int num1 = -1;
      try
      {
        bool flag = true;
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Generating  RSA pair for License[ " + IpkId + " ] and Length [ " + len + " ]");
        RsaKey returnClearRsaKey = this.doGenerateKeyPairReturnClearRSAKey(len, publicModulus);
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", " RSA pair Generated successfully for License[ " + IpkId + " ] and Length [ " + len + " ]");
        if (flag)
        {
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Storing RSA key pair in DB for License[ " + IpkId + " ] and Length [ " + len + " ]");
          num1 = this.dal.Insert_RSA_KeyPair(this.util.ByteArrayToString(returnClearRsaKey.publicModulus), this.util.ByteArrayToString(returnClearRsaKey.publicExponent), this.util.ByteArrayToString(returnClearRsaKey.privateExponent), this.util.ByteArrayToString(returnClearRsaKey.prime1), this.util.ByteArrayToString(returnClearRsaKey.prime2), this.util.ByteArrayToString(returnClearRsaKey.exponent1), this.util.ByteArrayToString(returnClearRsaKey.exponent2), this.util.ByteArrayToString(returnClearRsaKey.coefficient), this.util.ByteArrayToString(returnClearRsaKey.asn1PubKey), this.util.ByteArrayToString(returnClearRsaKey.asn1PrivKey), IpkId, len);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Result of Storing RSA key pair for IPK[ " + IpkId + " ] and Length [ " + len + " ] Result[ " + num1.ToString() + " ]");
        }
        if (num1 == -1)
        {
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Unable to Insert RSA key pair for IPK[ " + IpkId + " ] and Length [ " + len + " ] Result[ " + num1.ToString() + " ]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Exiting Method");
          return num1;
        }
        int num2 = Convert.ToInt32(len) / 8;
        string str1 = string.Format("{0:X}", (object) num2);
        string str2 = "01";
        string str3 = "";
        string str4 = "";
        string trackingnumber = "";
        string str5 = "";
        string str6 = string.Empty;
        string str7 = "01";
        string str8 = "01";
        string str9 = "22";
        string str10 = "23";
        string str11 = "02";
        int num3 = 20;
        string str12 = "0000";
        string empty = string.Empty;
        int num4 = -1;
        string str13 = string.Empty;
        string str14 = string.Empty;
        string str15 = string.Empty;
        string str16 = string.Empty;
        string str17 = string.Empty;
        string str18 = string.Empty;
        string str19 = string.Empty;
        string str20 = string.Empty;
        string str21 = string.Empty;
        string str22 = string.Empty;
        string str23 = string.Empty;
        string str24 = string.Empty;
        string str25 = string.Empty;
        string str26 = string.Empty;
        string str27 = string.Empty;
        string str28 = string.Empty;
        string str29 = string.Empty;
        string str30 = string.Empty;
        string str31 = string.Empty;
        string str32 = string.Empty;
        string str33 = string.Empty;
        string str34 = string.Empty;
        string str35 = string.Empty;
        DataTable dataTable1 = new DataTable();
        DataTable dataTable2 = this.dal.ReadLicDetails(Convert.ToInt32(IpkId));
        if (dataTable2.Rows.Count > 0)
        {
          str5 = dataTable2.Rows[0]["LICENCE_BranchCode"].ToString().Replace("F", "").Trim() + dataTable2.Rows[0]["LICENCE_module"].ToString().Trim() + dataTable2.Rows[0]["LICENCE_issuetype"].ToString().Trim();
          trackingnumber = dataTable2.Rows[0]["TRACKING_NUMBER"].ToString().Trim();
          string str36 = dataTable2.Rows[0]["LICENCE_DateExpiry"].ToString().Trim();
          str6 = str36.Substring(4, 2) + str36.Substring(2, 2);
          str4 = dataTable2.Rows[0]["LICENCE_ID"].ToString().Trim().PadRight(4, 'F') + dataTable2.Rows[0]["LICENCE_Environment"].ToString().Trim() + "0" + dataTable2.Rows[0]["LICENCE_ISSIGNED"].ToString().Trim();
          str3 = dataTable2.Rows[0]["IPK_EXPO"].ToString().Trim();
          str2 = dataTable2.Rows[0]["IPK_EXPO_LEN"].ToString().Trim();
          str13 = this.checkOdd(dataTable2.Rows[0]["LICENCE_ID"].ToString().Trim());
          str14 = this.checkOdd(dataTable2.Rows[0]["LICENCE_ClientName"].ToString().Trim());
          str15 = this.checkOdd(dataTable2.Rows[0]["LICENCE_WarningPeriod"].ToString().Trim());
          str16 = this.checkOdd(dataTable2.Rows[0]["LICENCE_Graceallowed"].ToString().Trim());
          str17 = this.checkOdd(dataTable2.Rows[0]["LICENCE_GracePeriod"].ToString().Trim());
          str18 = this.checkOdd(dataTable2.Rows[0]["LICENCE_BranchCode"].ToString().Trim());
          str19 = this.checkOdd(dataTable2.Rows[0]["LICENCE_DateFrom"].ToString().Trim());
          str20 = this.checkOdd(dataTable2.Rows[0]["LICENCE_DateExpiry"].ToString().Trim());
          str21 = this.checkOdd(dataTable2.Rows[0]["LICENCE_Environment"].ToString().Trim());
          str22 = this.checkOdd(dataTable2.Rows[0]["LICENCE_module"].ToString().Trim());
          str23 = this.checkOdd(dataTable2.Rows[0]["LICENCE_printerid"].ToString().Trim());
          str24 = this.checkOdd(dataTable2.Rows[0]["LICENCE_City"].ToString().Trim());
          str25 = this.checkOdd(dataTable2.Rows[0]["LICENCE_State"].ToString().Trim());
          str26 = this.checkOdd(dataTable2.Rows[0]["LICENCE_Zip"].ToString().Trim());
          str27 = this.checkOdd(dataTable2.Rows[0]["LICENCE_regdate"].ToString().Trim());
          str28 = this.checkOdd(dataTable2.Rows[0]["LICENCE_issuetype"].ToString().Trim());
          str29 = this.checkOdd(dataTable2.Rows[0]["LICENCE_ISENABLED"].ToString().Trim());
          str30 = this.checkOdd(dataTable2.Rows[0]["IPK_REMAINDER_LENGTH"].ToString().Trim());
          str31 = this.checkOdd(dataTable2.Rows[0]["IPK_REMAINDER"].ToString().Trim());
          str32 = this.checkOdd(dataTable2.Rows[0]["HASH_DATA"].ToString().Trim());
          str33 = this.checkOdd(dataTable2.Rows[0]["IS_REQ"].ToString().Trim());
          str34 = this.checkOdd(dataTable2.Rows[0]["LICENCE_ISSIGNED"].ToString().Trim());
          str35 = this.checkOdd(dataTable2.Rows[0]["LICENCE_ENCRYPTED"].ToString().Trim());
        }
        string hex1 = this.util.ByteArrayToString(returnClearRsaKey.publicModulus);
        string hex2 = this.util.ByteArrayToString(returnClearRsaKey.publicExponent);
        string hex3 = this.util.ByteArrayToString(returnClearRsaKey.privateExponent);
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "RS_PUB_MOD [ " + hex1 + " ]");
        string str37 = str9 + str1 + hex1 + str2 + str3 + trackingnumber;
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "unsigned_ipkRequest [ " + str37 + " ]");
        int num5 = (str10 + str4 + str12 + str11 + str5 + str6 + trackingnumber + str7 + str8 + str1 + str2 + str3).Length / 2 + num3;
        int length = Convert.ToInt32(num2 - num5) * 2;
        string str38 = hex1.Substring(0, length);
        string strInput = str10 + str4 + str12 + str11 + str5 + str6 + trackingnumber + str7 + str8 + str1 + str2 + str38 + str3;
        byte[] numArray = new byte[32];
        string str39 = this.util.ByteArrayToString(new SHA1CryptoServiceProvider().ComputeHash(this.util.String_To_Bytes(strInput)));
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Hash [ " + str39 + " ]");
        string hex4 = strInput + str39;
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "self_signed_Ipk_Req [ " + hex4 + " ]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "RS_PUB_EXP [ " + hex2 + " ]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "RS_PRI_EXP [ " + hex3 + " ]");
        byte[] byteArray = HelperFunctions.StringToByteArray(hex4);
        string encryptedData = HelperFunctions.ByteArrayToString(this.doRSASign(HelperFunctions.StringToByteArray(hex1), HelperFunctions.StringToByteArray(hex2), HelperFunctions.StringToByteArray(hex3), byteArray));
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", " signedData [ " + encryptedData + " ]");
        string str40 = HelperFunctions.ByteArrayToString(this.PublicDecryption(encryptedData, HelperFunctions.ByteArrayToString(returnClearRsaKey.publicExponent), HelperFunctions.ByteArrayToString(returnClearRsaKey.publicModulus)));
        if (str39 == str40.Substring(str40.Length - 40))
        {
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Hash Validate Successfully");
          num4 = this.dal.Update_License_Details(IpkId, str39, str37 + encryptedData, str39, trackingnumber);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Result of Update_License_Details " + num4.ToString());
        }
        return num4;
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        return -1;
      }
    }

    [WebMethod]
    public string SignLicense(string len, string CertificateId, string P1, string P2)
    {
      this.Method_Name = nameof (SignLicense);
      try
      {
        int num1 = Convert.ToInt32(len) / 8;
        string.Format("{0:X}", (object) num1);
        string str1 = "01";
        string PublicExp = "";
        string empty1 = string.Empty;
        int num2 = 20;
        string str2 = "01";
        string hex1 = "";
        string hex2 = "";
        string empty2 = string.Empty;
        int num3 = -1;
        string empty3 = string.Empty;
        string empty4 = string.Empty;
        DataTable dataTable1 = new DataTable();
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Reading CA Certificate");
        DataTable dataTable2 = this.dal.ReadCAIndex(Convert.ToInt32(CertificateId));
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "CA Certificate Read[ " + dataTable2.Rows.Count.ToString() + " ]");
        if (dataTable2.Rows.Count > 0)
        {
          str2 = dataTable2.Rows[0]["MODULUS"].ToString();
          hex1 = dataTable2.Rows[0]["EXPONENT"].ToString();
          empty3 = dataTable2.Rows[0]["RID"].ToString();
          hex2 = "2552BD1A9719DA18C273DF73AFAE53EDF711BDFE91850E519E41491C499FD3CA4A62F02507EC5B084DF90CF8F80C32D34C2D625B68884A604E42584DB9BAD0FCBFF0FC4FC0D4D0E4CE7E9AFE2CB6C2BC4557CAE652E859B5C365B90413E4467B838FFBF2860438F637A9462ADAA48A6A7FC6E2747077432EF31594A3CBDEC086B4FE87CABD6FA214C06264ADF1D74DFB74067082D8A63AA703D81D4D2B1A67B309BF87203649913A3C51DA678E0EBCC7";
          empty1 = dataTable2.Rows[0]["EXPIRY"].ToString();
        }
        if (P1.Length > 0)
        {
          PublicExp = "03";
          str1 = "01";
        }
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "RS_PUB_MOD [ " + str2 + " ]");
        string str3 = P1;
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "unsigned_ipkRequest [ " + str3 + " ]");
        int num4 = P2.Length / 2 + num2;
        int num5 = Convert.ToInt32(num1 - num4) * 2;
        string strInput = P2;
        byte[] numArray = new byte[32];
        string str4 = this.util.ByteArrayToString(new SHA1CryptoServiceProvider().ComputeHash(this.util.String_To_Bytes(strInput)));
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Hash [ " + str4 + " ]");
        string hex3 = strInput + str4 + "BC";
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "self_signed_Ipk_Req [ " + hex3 + " ]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "RS_PUB_EXP [ " + hex1 + " ]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "RS_PRI_EXP [ " + hex2 + " ]");
        byte[] byteArray = HelperFunctions.StringToByteArray(hex3);
        string encryptedData = HelperFunctions.ByteArrayToString(this.doRSASign(HelperFunctions.StringToByteArray(str2), HelperFunctions.StringToByteArray(hex1), HelperFunctions.StringToByteArray(hex2), byteArray));
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", " signedData [ " + encryptedData + " ]");
        string str5 = HelperFunctions.ByteArrayToString(this.PublicDecryption(encryptedData, PublicExp, str2));
        string str6;
        if (str4 == str5.Substring(str5.Length - 42, 40))
        {
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Hash Validate Successfully");
          str6 = str3 + encryptedData;
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Result of Update_License_Details " + num3.ToString());
        }
        else
        {
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Hash Not Validated");
          str6 = "Hash Not Validated";
        }
        return str6;
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        return ex.Message;
      }
    }

    [WebMethod]
    public string checkOdd(string input_value)
    {
      int num = input_value.Count<char>();
      return num % 2 == 0 ? input_value : input_value.PadLeft(num + 1, '0');
    }

    [WebMethod]
    public byte[] PublicDecryption(string encryptedData, string PublicExp = null, string PublicMod = null)
    {
      this.Method_Name = nameof (PublicDecryption);
      BigInteger exponent = new BigInteger();
      BigInteger modulus = new BigInteger();
      try
      {
        if (PublicExp != null && PublicMod != null)
        {
          exponent = this.HexToBigInt(PublicExp);
          modulus = this.HexToBigInt(PublicMod);
        }
        return ((IEnumerable<byte>) BigInteger.ModPow(this.HexToBigInt(encryptedData), exponent, modulus).ToByteArray()).Reverse<byte>().ToArray<byte>();
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        return (byte[]) null;
      }
    }

    public BigInteger HexToBigInt(string HexString)
    {
      BigInteger bigInteger = BigInteger.Parse(HexString, NumberStyles.AllowHexSpecifier);
      if (bigInteger < 0L)
        bigInteger = BigInteger.Pow((BigInteger) 2, HexString.Length * 4) - BigInteger.Abs(bigInteger);
      return bigInteger;
    }

    [WebMethod]
    public string Calculate_HASH(string input_value) => this.util.ByteArrayToString(new SHA1CryptoServiceProvider().ComputeHash(this.util.String_To_Bytes(input_value)));

    [WebMethod]
    public string Validate_SystemLicence(string signed_ipk_value, string RSA_LEN)
    {
      this.Method_Name = nameof (Validate_SystemLicence);
      this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "signed_ipk_value : " + signed_ipk_value);
      this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "RSA_LEN : " + RSA_LEN);
      SHA1 shA1 = (SHA1) new SHA1CryptoServiceProvider();
      string empty1 = string.Empty;
      string empty2 = string.Empty;
      string empty3 = string.Empty;
      string empty4 = string.Empty;
      string empty5 = string.Empty;
      DataTable dataTable1 = new DataTable();
      string empty6 = string.Empty;
      string empty7 = string.Empty;
      string empty8 = string.Empty;
      try
      {
        string str1;
        string key_type;
        int startIndex;
        if (Convert.ToInt32(RSA_LEN) == 1976)
        {
          str1 = signed_ipk_value.Substring(0, 106).Substring(30, 70);
          key_type = signed_ipk_value.Substring(104, 2);
          startIndex = 106;
        }
        else
        {
          str1 = signed_ipk_value.Substring(0, 108).Substring(28, 72);
          key_type = signed_ipk_value.Substring(106, 2);
          startIndex = 108;
        }
        DataTable dataTable2 = this.dal.ReadCA_MOD_EXPO(key_type);
        string PublicMod = dataTable2.Rows[0]["MODULUS"].ToString();
        string PublicExp = dataTable2.Rows[0]["EXPONENT"].ToString();
        int length = (int) Convert.ToInt16(dataTable2.Rows[0]["KEY_LENGTH"].ToString()) / 4;
        string encryptedData = signed_ipk_value.Substring(startIndex, length);
        string str2 = HelperFunctions.ByteArrayToString(this.PublicDecryption(encryptedData, PublicExp, PublicMod));
        string str3 = str2.Substring(28, str2.Length - 72);
        str2.Substring(str3.Length + 30, 40);
        this.util.ByteArrayToString(shA1.ComputeHash(this.util.String_To_Bytes(str2.Substring(2, str2.Length - 44) + str1 + PublicExp)));
        return str2.Substring(16, 6) + "~03~" + str1 + "~" + encryptedData + "~" + str2;
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        return ex.Message;
      }
    }

    [WebMethod]
    public string Validate_VISA_IPK(string signed_ipk_value, string RSA_LEN)
    {
      this.Method_Name = nameof (Validate_VISA_IPK);
      this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Validate_VISA_IPK starts");
      this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Recieved Data signed_ipk_value : [" + signed_ipk_value + "]  and RSA_LEN : [" + RSA_LEN + "]");
      SHA1 shA1 = (SHA1) new SHA1CryptoServiceProvider();
      string empty1 = string.Empty;
      string empty2 = string.Empty;
      string empty3 = string.Empty;
      string empty4 = string.Empty;
      string empty5 = string.Empty;
      DataTable dataTable1 = new DataTable();
      string empty6 = string.Empty;
      string empty7 = string.Empty;
      string empty8 = string.Empty;
      try
      {
        string str1;
        string str2;
        string key_type;
        int startIndex;
        if (Convert.ToInt32(RSA_LEN) == 1976)
        {
          str1 = signed_ipk_value.Substring(0, 106);
          str2 = str1.Substring(30, 70);
          key_type = signed_ipk_value.Substring(104, 2);
          startIndex = 106;
        }
        else if (RSA_LEN == "1920")
        {
          str1 = signed_ipk_value.Substring(0, 92);
          str2 = str1.Substring(30, 56);
          key_type = signed_ipk_value.Substring(90, 2);
          startIndex = 92;
        }
        else
        {
          str1 = signed_ipk_value.Substring(0, 108);
          str2 = str1.Substring(30, 72);
          key_type = signed_ipk_value.Substring(106, 2);
          startIndex = 108;
        }
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "part1 : [" + str1 + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "ipk_remainder : [" + str2 + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "key_type : [" + key_type + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "part2_len : [" + startIndex.ToString() + "]");
        DataTable dataTable2 = this.dal.ReadCA_MOD_EXPO(key_type);
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "dt Count : [" + dataTable2.Rows.Count.ToString() + "]");
        string PublicMod = dataTable2.Rows[0]["MODULUS"].ToString();
        string PublicExp = dataTable2.Rows[0]["EXPONENT"].ToString();
        int length = (int) Convert.ToInt16(dataTable2.Rows[0]["KEY_LENGTH"].ToString()) / 4;
        string encryptedData = signed_ipk_value.Substring(startIndex, length);
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "ca_mod : [" + PublicMod + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "ca_expo : [" + PublicExp + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "length : [" + length.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "part2 data : [" + encryptedData + "]");
        string str3 = HelperFunctions.ByteArrayToString(this.PublicDecryption(encryptedData, PublicExp, PublicMod));
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "decrypted_data : [" + str3 + "]");
        string str4 = str3.Substring(30, str3.Length - 72);
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "leftmost : [" + str4 + "]");
        string str5 = str3.Substring(str4.Length + 30, 40);
        string str6 = this.util.ByteArrayToString(shA1.ComputeHash(this.util.String_To_Bytes(str3.Substring(2, str3.Length - 44) + str2 + PublicExp)));
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Recovered Hash : [" + str6 + "] = IPK Hash : [" + str5 + "]");
        string str7;
        if (str5 == str6)
          str7 = str3.Substring(14, 6) + "~03~" + str2 + "~" + encryptedData + "~" + str3;
        else
          str7 = "Hash Not Matched";
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "return_value : [" + str7 + "]");
        return str7;
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        return ex.Message;
      }
    }

    [WebMethod]
    public string Validate_MCHIP_IPK(string signed_ipk_value, string RSA_LEN)
    {
      this.Method_Name = nameof (Validate_MCHIP_IPK);
      this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Validate_MCHIP_IPK starts");
      this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Recieved Data signed_ipk_value : [" + signed_ipk_value + "]  and RSA_LEN : [" + RSA_LEN + "]");
      SHA1 shA1 = (SHA1) new SHA1CryptoServiceProvider();
      string empty1 = string.Empty;
      string empty2 = string.Empty;
      string empty3 = string.Empty;
      string empty4 = string.Empty;
      string empty5 = string.Empty;
      DataTable dataTable1 = new DataTable();
      string empty6 = string.Empty;
      string empty7 = string.Empty;
      string empty8 = string.Empty;
      try
      {
        string str1 = signed_ipk_value.Substring(0, 8);
        string str2 = signed_ipk_value.Substring(8, 6);
        string key_type = signed_ipk_value.Substring(14, 2);
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "BIN : [" + str1 + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "tracking_num : [" + str2 + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "key_type : [" + key_type + "]");
        string str3;
        string str4;
        int startIndex;
        if (RSA_LEN == "1976")
        {
          str3 = signed_ipk_value.Substring(0, 16);
          str4 = signed_ipk_value.Substring(16, 70);
          startIndex = 88;
        }
        else if (RSA_LEN == "1920")
        {
          str3 = signed_ipk_value.Substring(0, 16);
          str4 = signed_ipk_value.Substring(16, 56);
          startIndex = 74;
        }
        else
        {
          str3 = signed_ipk_value.Substring(0, 16);
          str4 = signed_ipk_value.Substring(16, 72);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "ipk_remainder : [" + str4 + "]");
          startIndex = 90;
        }
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "part1 : [" + str3 + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "ipk_remainder : [" + str4 + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "part2_len : [" + startIndex.ToString() + "]");
        DataTable dataTable2 = this.dal.ReadCA_MOD_EXPO(key_type);
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "dt count : [" + dataTable2.Rows.Count.ToString() + "]");
        string PublicMod = dataTable2.Rows[0]["MODULUS"].ToString();
        string PublicExp = dataTable2.Rows[0]["EXPONENT"].ToString();
        int length = (int) Convert.ToInt16(dataTable2.Rows[0]["KEY_LENGTH"].ToString()) / 4;
        string encryptedData = signed_ipk_value.Substring(startIndex, length);
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "ca_mod : [" + PublicMod + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "ca_expo : [" + PublicExp + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "length : [" + length.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "part2 data : [" + encryptedData + "]");
        string str5 = HelperFunctions.ByteArrayToString(this.PublicDecryption(encryptedData, PublicExp, PublicMod));
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "decrypted_data : [" + str5 + "]");
        string str6 = str5.Substring(str5.Length - 42, 40);
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "hash_value : [" + str6 + "]");
        string str7 = this.util.ByteArrayToString(shA1.ComputeHash(this.util.String_To_Bytes(str5.Substring(2, str5.Length - 44) + str4 + PublicExp)));
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "recovered_hash : [" + str7 + "]");
        string str8;
        if (str6 == str7)
          str8 = str5.Substring(16, 6) + "~" + PublicExp + "~" + str4 + "~" + encryptedData + "~" + str5;
        else
          str8 = "Hash Not Matched";
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "return_value : [" + str8 + "]");
        return str8;
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        return ex.Message;
      }
    }

    [WebMethod]
    public string NineFourSix_DataCreation(
      string ICC_CertificateData,
      string SFIData,
      string IpkIndex,
      int ICCPubKeyLen = 128)
    {
      lock (this)
      {
        this.Method_Name = nameof (NineFourSix_DataCreation);
        try
        {
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "9F46 Data starts");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "ICC_CertificateData [ " + ICC_CertificateData + " ]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "SFIData [ " + SFIData + " ]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "IpkIndex [ " + IpkIndex + " ]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "ICCPubKeyLen [ " + ICCPubKeyLen.ToString() + " ]");
          string strInput = ICC_CertificateData + SFIData;
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "inputSHA01String [ICC_CertificateData + SFIData] [ " + strInput + " ]");
          DataTable dataTable1 = new DataTable();
          string hex1 = "01";
          string hex2 = "";
          string hex3 = "";
          string empty1 = string.Empty;
          DataTable dataTable2 = this.dal.Read_RSA_Details(IpkIndex);
          if (dataTable2.Rows.Count > 0)
          {
            hex1 = dataTable2.Rows[0]["RS_PUB_MOD"].ToString().Trim();
            hex2 = dataTable2.Rows[0]["RS_PUB_EXP"].ToString().Trim();
            hex3 = dataTable2.Rows[0]["RS_PRI_EXP"].ToString().Trim();
            int num = hex1.Length / 2;
          }
          string empty2 = string.Empty;
          byte[] numArray = new byte[32];
          string str1 = this.util.ByteArrayToString(new SHA1CryptoServiceProvider().ComputeHash(this.util.String_To_Bytes(strInput)));
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "hash [ " + str1 + " ]");
          ICC_CertificateData = "6A" + ICC_CertificateData + str1 + "BC";
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "ICC_CertificateData [ " + ICC_CertificateData + "]");
          byte[] byteArray = HelperFunctions.StringToByteArray(ICC_CertificateData);
          string str2 = HelperFunctions.ByteArrayToString(this.doRSASign(HelperFunctions.StringToByteArray(hex1), HelperFunctions.StringToByteArray(hex2), HelperFunctions.StringToByteArray(hex3), byteArray));
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "9F46_Certificate [ " + str2 + " ]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "9F46 Data Created");
          return str2;
        }
        catch (Exception ex)
        {
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
          return ex.Message;
        }
      }
    }

    [WebMethod]
    public string NineThree_DataCreation(string inputString, string IpkIndex)
    {
      lock (this)
      {
        this.Method_Name = nameof (NineThree_DataCreation);
        try
        {
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "93 Data creation starts");
          DataTable dataTable1 = new DataTable();
          string hex1 = "01";
          string hex2 = "";
          string hex3 = "";
          string str1 = "";
          string empty1 = string.Empty;
          DataTable dataTable2 = this.dal.Read_RSA_Details(IpkIndex);
          if (dataTable2.Rows.Count > 0)
          {
            hex1 = dataTable2.Rows[0]["RS_PUB_MOD"].ToString().Trim();
            hex2 = dataTable2.Rows[0]["RS_PUB_EXP"].ToString().Trim();
            hex3 = dataTable2.Rows[0]["RS_PRI_EXP"].ToString().Trim();
            str1 = dataTable2.Rows[0]["RS_PRIME1"].ToString().Trim();
          }
          string empty2 = string.Empty;
          byte[] numArray = new byte[32];
          string str2 = this.util.ByteArrayToString(new SHA1CryptoServiceProvider().ComputeHash(this.util.String_To_Bytes(inputString)));
          int num1 = 176;
          string str3 = "6A" + inputString.Substring(0, 8);
          int num2 = (num1 - 26) * 2;
          for (int index = 0; index < num2; ++index)
            str3 += "B";
          byte[] byteArray = HelperFunctions.StringToByteArray(str3 + str2 + "BC");
          string str4 = HelperFunctions.ByteArrayToString(this.doRSASign(HelperFunctions.StringToByteArray(hex1), HelperFunctions.StringToByteArray(hex2), HelperFunctions.StringToByteArray(hex3), byteArray));
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", " signedData [ " + str4 + " ]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "(93Data [ " + str4 + " ]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "93 Data creation Ends");
          return str4;
        }
        catch (Exception ex)
        {
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
          return ex.Message;
        }
      }
    }

    public string RSASign()
    {
      this.Method_Name = nameof (RSASign);
      try
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "RSASign starts");
        DataTable dataTable = new DataTable();
        string empty = string.Empty;
        string hex1 = "B121EDBBCA623A957FBD432246C24D00A3BC077CCAC7AB78EAD7EE8EE3293C8306F190C4BAAB94A62393D1B27C7F380277274FE3842DD39435BD0F553D25BAA2F8C3BF1EBF42E04B9997BE18E4E41C262A233EE57D49F1556D9A0A44FC2D2E4F2BF5A0DD71E73038EA8CE1C27EFD20E5E17B4BA81229FBE8AC719BAFEA6AC3F005C86D9C9F1A37D6FD7CB1E88E9A6FA6432DA6858ABA00040478025A7DD6A4AC839DE933569122D08222057012BBD083";
        string hex2 = "03";
        string hex3 = "76169E7D3196D1B8FFD38216D9D6DE006D2804FDDC851CFB473A9F09ECC6285759F66083271D0DC417B7E121A854D001A4C4DFED02C937B823D35F8E28C3D1C1FB2D2A147F81EADD110FD410989812C41C177F43A8DBF637D7C8AF67C0893B9AAF43A745FEC96985EFC424ACE57637C7199D8CB4BD82397030933A700C1F757DF192C642333667B3D388538DAAA2EF4718DC4EF5A57702F5E803956AB22764ABDF75674F26533AF4B4136D9A142796FB";
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "RS_PUB_MOD:" + hex1);
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "RS_PUB_EXP:" + hex2);
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "RS_PRI_EXP:" + hex3);
        byte[] byteArray = HelperFunctions.StringToByteArray("231010000002416638FF12239065890101B001B121EDBBCA623A957FBD432246C24D00A3BC077CCAC7AB78EAD7EE8EE3293C8306F190C4BAAB94A62393D1B27C7F380277274FE3842DD39435BD0F553D25BAA2F8C3BF1EBF42E04B9997BE18E4E41C262A233EE57D49F1556D9A0A44FC2D2E4F2BF5A0DD71E73038EA8CE1C27EFD20E5E17B4BA81229FBE8AC719BAFEA6AC3F005C86D9C9F1A37D60398DAA1A72D2310C18F534BCC8BD375CB0B316097");
        return HelperFunctions.ByteArrayToString(this.doRSASign(HelperFunctions.StringToByteArray(hex1), HelperFunctions.StringToByteArray(hex2), HelperFunctions.StringToByteArray(hex3), byteArray));
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        return ex.Message;
      }
    }

    [WebMethod]
    public string RSASignRecover()
    {
      this.Method_Name = nameof (RSASignRecover);
      try
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "RSASignRecover starts");
        DataTable dataTable = new DataTable();
        string empty = string.Empty;
        string hex1 = "B121EDBBCA623A957FBD432246C24D00A3BC077CCAC7AB78EAD7EE8EE3293C8306F190C4BAAB94A62393D1B27C7F380277274FE3842DD39435BD0F553D25BAA2F8C3BF1EBF42E04B9997BE18E4E41C262A233EE57D49F1556D9A0A44FC2D2E4F2BF5A0DD71E73038EA8CE1C27EFD20E5E17B4BA81229FBE8AC719BAFEA6AC3F005C86D9C9F1A37D6FD7CB1E88E9A6FA6432DA6858ABA00040478025A7DD6A4AC839DE933569122D08222057012BBD083";
        string hex2 = "03";
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "RS_PUB_MOD:" + hex1);
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "RS_PUB_EXP:" + hex2);
        byte[] byteArray = HelperFunctions.StringToByteArray("146FBBE1E14A9E845C000C76A159A8813EF3F771F6B74C2AD7DDF3C16CE7657501B684C34E47006C72396AE495FFA9704558A15835CD691D5B4FA556812CE4398BC0BFB621004516B9E8BE42BFA0F5F68CF876829D5CB1432EF4AA80E1E84EB02E1E3E299036F74739561CBEBB497A6F394D71B8D087105506DB40A587ADC0B160FFCD78640D3EECED2DC2F4E59B04200D8FAA05ABB7753907982EC8ED0FA70F55DC58940268C73EE11B10846FFEAAE0");
        string str = HelperFunctions.ByteArrayToString(this.doRSASignRecover(HelperFunctions.StringToByteArray(hex1), HelperFunctions.StringToByteArray(hex2), byteArray));
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "RSASignRecover ends");
        return str;
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        return ex.Message;
      }
    }

    [WebMethod]
    public byte[] doRSASignRecover(byte[] RSAPubMod, byte[] RSAPubExp, byte[] SignatureData)
    {
      this.Method_Name = "RSASignRecover";
      try
      {
        if (KMUService.session == null)
        {
          this._SingleInstance = SingletonHSMClass.GetInstanceHSM();
          KMUService.session = this._SingleInstance.instancename;
        }
        List<IObjectAttribute> attributes = new List<IObjectAttribute>();
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, false));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, SingletonHSMClass.ApplicationName));
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "SingeltonHSMClass.ApplicationName    :" + SingletonHSMClass.ApplicationName);
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, true));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY_RECOVER, true));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, true));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS_BITS, Convert.ToUInt64(SignatureData.Length * 8)));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_PUBLIC_EXPONENT, RSAPubExp));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS, RSAPubMod));
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "publicKeyAttributes set");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "CKA_LABEL [ " + SingletonHSMClass.ApplicationName + " ]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "RSAPubMod [ " + HelperFunctions.ByteArrayToString(RSAPubMod) + " ]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "RSAPubExp [ " + HelperFunctions.ByteArrayToString(RSAPubExp) + " ]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "ModulusBits [ " + Convert.ToUInt64(SignatureData.Length * 8).ToString() + " ]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "ClearData [ " + HelperFunctions.ByteArrayToString(SignatureData) + " ]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "privateKeyAttributes set");
        IObjectHandle objectHandle = KMUService.session.CreateObject(attributes);
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "CreateObject Done");
        IMechanism mechanism = SingletonHSMClass.factories.MechanismFactory.Create(CKM.CKM_RSA_X_509);
        bool isValid = false;
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "VerifyRecover starts");
        byte[] numArray = KMUService.session.VerifyRecover(mechanism, objectHandle, SignatureData, out isValid);
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "VerifyRecover ends");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "IsValidSignature [" + isValid.ToString() + "]");
        KMUService.session.DestroyObject(objectHandle);
        return numArray;
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        return (byte[]) null;
      }
    }

    [WebMethod]
    public string CreateKey(string Key_Label, string Key_Value, string key_type)
    {
      this.Method_Name = nameof (CreateKey);
      try
      {
        CKK ckk = CKK.CKK_DES2;
        CKM type = CKM.CKM_DES2_KEY_GEN;
        string str1 = key_type;
        if (!(str1 == "AES"))
        {
          if (!(str1 == "DES"))
          {
            if (!(str1 == "DES2"))
            {
              if (!(str1 == "DES3"))
              {
                if (str1 == "SEC")
                {
                  ckk = CKK.CKK_GENERIC_SECRET;
                  type = CKM.CKM_GENERIC_SECRET_KEY_GEN;
                }
              }
              else
              {
                ckk = CKK.CKK_DES3;
                type = CKM.CKM_DES3_KEY_GEN;
              }
            }
            else
            {
              ckk = CKK.CKK_DES2;
              type = CKM.CKM_DES2_KEY_GEN;
            }
          }
          else
          {
            ckk = CKK.CKK_DES;
            type = CKM.CKM_DES_KEY_GEN;
          }
        }
        else
        {
          ckk = CKK.CKK_AES;
          type = CKM.CKM_AES_KEY_GEN;
        }
        if (KMUService.session == null)
        {
          this._SingleInstance = SingletonHSMClass.GetInstanceHSM();
          KMUService.session = this._SingleInstance.instancename;
        }
        List<IObjectAttribute> objectAttributeList = new List<IObjectAttribute>()
        {
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, false),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, ckk),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, true),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, true),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true)
        };
        SingletonHSMClass.factories.MechanismFactory.Create(type);
        Utility utility = new Utility();
        string str2 = "";
        str2 = "10101010101010101010101010101010";
        byte[] byteArray = HelperFunctions.StringToByteArray(utility.GetOddParityDESKEY(Key_Value));
        return KMUService.session.CreateObject(new List<IObjectAttribute>()
        {
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, Key_Label),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, ckk),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE, byteArray)
        }).ObjectId.ToString();
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        return ex.Message;
      }
    }

    [WebMethod]
    public string generateAndCreateKeyObj()
    {
      try
      {
        if (KMUService.session == null)
        {
          this._SingleInstance = SingletonHSMClass.GetInstanceHSM();
          KMUService.session = this._SingleInstance.instancename;
        }
        List<IObjectAttribute> objectAttributeList1 = new List<IObjectAttribute>()
        {
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, false),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_DES2),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, true),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, true),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true)
        };
        SingletonHSMClass.factories.MechanismFactory.Create(CKM.CKM_DES2_KEY_GEN);
        byte[] byteArray = HelperFunctions.StringToByteArray(new Utility().GetOddParityDESKEY("10101010101010101010101010101010"));
        IObjectHandle keyHandle = KMUService.session.CreateObject(new List<IObjectAttribute>()
        {
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "Imported key1"),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_DES2),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE, byteArray)
        });
        IMechanism mechanism = SingletonHSMClass.factories.MechanismFactory.Create(CKM.CKM_DES3_ECB);
        List<IObjectAttribute> objectAttributeList2 = new List<IObjectAttribute>()
        {
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "LMK_MASTER_KEY"),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_DES3),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, true),
          SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, true)
        };
        IObjectHandle akeyObject = KMUService.findAKeyObject("LMK_MASTER_KEY");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "hLMKKey [" + akeyObject.ObjectId.ToString() + "]");
        return HelperFunctions.ByteArrayToString(KMUService.session.WrapKey(mechanism, akeyObject, keyHandle));
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        return ex.Message;
      }
    }

    [WebMethod]
    public string Check_Library(string plainKey, string KEYNAME, bool cbc = false, int counter = 0)
    {
      lock (this)
      {
        string empty = string.Empty;
        this.Method_Name = nameof (Check_Library);
        string str = "00000000000000000000000000000000";
        try
        {
          if (KMUService.session == null || this._SingleInstance.counter == 0)
          {
            this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Session is NULL");
            this._SingleInstance = SingletonHSMClass.GetInstanceHSM();
            KMUService.session = this._SingleInstance.instancename;
          }
          IObjectHandle akeyObject = KMUService.findAKeyObject(KEYNAME);
          LogClass logWrite1 = this.Log_write;
          string strIpAddress1 = this.strIpAddress;
          string className1 = this.Class_Name;
          string methodName1 = this.Method_Name;
          ulong objectId = akeyObject.ObjectId;
          string message1 = "Object Found Successfully [" + objectId.ToString() + "]";
          logWrite1.LogWrite(strIpAddress1, className1, methodName1, "Information", message1);
          if (akeyObject == null)
          {
            this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "[" + KEYNAME + "] Not Found");
            return "No Key Found";
          }
          LogClass logWrite2 = this.Log_write;
          string strIpAddress2 = this.strIpAddress;
          string className2 = this.Class_Name;
          string methodName2 = this.Method_Name;
          objectId = akeyObject.ObjectId;
          string message2 = "Object Found" + objectId.ToString();
          logWrite2.LogWrite(strIpAddress2, className2, methodName2, "Information", message2);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "mechanism_wrap_encrypt_decrypt");
          IMechanism mechanism;
          if (!cbc)
          {
            this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "CBC False");
            mechanism = SingletonHSMClass.factories.MechanismFactory.Create(CKM.CKM_DES3_ECB);
          }
          else
          {
            this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "CBC True");
            mechanism = SingletonHSMClass.factories.MechanismFactory.Create(CKM.CKM_DES3_CBC);
          }
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Encrypting Data");
          Stream streamFromString = (Stream) KMUService.GenerateStreamFromString(plainKey);
          byte[] ba = KMUService.session.Encrypt(mechanism, akeyObject, HelperFunctions.StringToByteArray(plainKey));
          str = HelperFunctions.ByteArrayToString(ba);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Calling Thread");
          return HelperFunctions.ByteArrayToString(ba);
        }
        catch (Exception ex)
        {
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
          return ex.Message;
        }
      }
    }

    [WebMethod]
    public string Encrypt_PGP_Pass(string plainKey, string KEYNAME, bool cbc = false)
    {
      lock (this)
      {
        this.Method_Name = nameof (Encrypt_PGP_Pass);
        string empty = string.Empty;
        try
        {
          if (KMUService.session == null || this._SingleInstance.counter == 0)
          {
            this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Session is NULL");
            this._SingleInstance = SingletonHSMClass.GetInstanceHSM();
            KMUService.session = this._SingleInstance.instancename;
          }
          IObjectHandle akeyObject = KMUService.findAKeyObject(KEYNAME);
          LogClass logWrite1 = this.Log_write;
          string strIpAddress1 = this.strIpAddress;
          string className1 = this.Class_Name;
          string methodName1 = this.Method_Name;
          ulong objectId = akeyObject.ObjectId;
          string message1 = "Object Found Successfully [" + objectId.ToString() + "]";
          logWrite1.LogWrite(strIpAddress1, className1, methodName1, "Information", message1);
          if (akeyObject == null)
          {
            this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "[" + KEYNAME + "] Not Found");
            return "No Key Found";
          }
          LogClass logWrite2 = this.Log_write;
          string strIpAddress2 = this.strIpAddress;
          string className2 = this.Class_Name;
          string methodName2 = this.Method_Name;
          objectId = akeyObject.ObjectId;
          string message2 = "Object Found" + objectId.ToString();
          logWrite2.LogWrite(strIpAddress2, className2, methodName2, "Information", message2);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "mechanism_wrap_encrypt_decrypt");
          IMechanism mechanism;
          if (!cbc)
          {
            this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "CBC False");
            mechanism = SingletonHSMClass.factories.MechanismFactory.Create(CKM.CKM_DES3_ECB);
          }
          else
          {
            this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "CBC True");
            mechanism = SingletonHSMClass.factories.MechanismFactory.Create(CKM.CKM_DES3_CBC);
          }
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Encrypting Data");
          Stream streamFromString = (Stream) KMUService.GenerateStreamFromString(plainKey);
          byte[] bytes = Encoding.ASCII.GetBytes(plainKey);
          byte[] ba = KMUService.session.Encrypt(mechanism, akeyObject, bytes);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Encrypted Data Successfully [" + HelperFunctions.ByteArrayToString(ba) + "]");
          return HelperFunctions.ByteArrayToString(ba);
        }
        catch (Exception ex)
        {
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
          return ex.Message;
        }
      }
    }

    public static MemoryStream GenerateStreamFromString(string value) => new MemoryStream(Encoding.UTF8.GetBytes(value ?? ""));

    [WebMethod]
    public string decrypt_Key(string encryptedKey, string keyName, bool cbc = false)
    {
      lock (this)
      {
        string empty = string.Empty;
        this.Method_Name = "DecryptKey";
        try
        {
          if (KMUService.session == null || this._SingleInstance.counter == 0)
          {
            this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Session is NULL");
            this._SingleInstance = SingletonHSMClass.GetInstanceHSM();
            KMUService.session = this._SingleInstance.instancename;
          }
          IObjectHandle akeyObject = KMUService.findAKeyObject(keyName);
          LogClass logWrite1 = this.Log_write;
          string strIpAddress1 = this.strIpAddress;
          string className1 = this.Class_Name;
          string methodName1 = this.Method_Name;
          ulong objectId = akeyObject.ObjectId;
          string message1 = "Object Found Successfully [" + objectId.ToString() + "]";
          logWrite1.LogWrite(strIpAddress1, className1, methodName1, "Information", message1);
          if (akeyObject == null)
          {
            this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "[" + keyName + "] Not Found");
            return "No Key Found";
          }
          LogClass logWrite2 = this.Log_write;
          string strIpAddress2 = this.strIpAddress;
          string className2 = this.Class_Name;
          string methodName2 = this.Method_Name;
          objectId = akeyObject.ObjectId;
          string message2 = "Object Found" + objectId.ToString();
          logWrite2.LogWrite(strIpAddress2, className2, methodName2, "Information", message2);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "mechanism_wrap_encrypt_decrypt");
          IMechanism mechanism;
          if (!cbc)
          {
            this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "CBC False");
            mechanism = SingletonHSMClass.factories.MechanismFactory.Create(CKM.CKM_DES3_ECB);
          }
          else
          {
            this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "CBC True");
            mechanism = SingletonHSMClass.factories.MechanismFactory.Create(CKM.CKM_DES3_CBC);
          }
          string message3 = HelperFunctions.ByteArrayToString(KMUService.session.Decrypt(mechanism, akeyObject, HelperFunctions.StringToByteArray(encryptedKey)));
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", message3);
          KMUService.session.Logout();
          return message3;
        }
        catch (Exception ex)
        {
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
          return ex.Message;
        }
      }
    }

    [WebMethod]
    public RsaKey CreateRSAPAIR(string len, string rsaname)
    {
      byte[] byteArray = HelperFunctions.StringToByteArray("03");
      List<CKA> attributes1 = new List<CKA>();
      List<CKA> attributes2 = new List<CKA>();
      RsaKey rsaKey = new RsaKey();
      this.Method_Name = nameof (CreateRSAPAIR);
      try
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Creating RSA Key Pair with Name[" + rsaname + "]");
        if (!this.GenerateRSAKeyObject(rsaname, Convert.ToUInt64(len), byteArray, false))
        {
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Unable to Create RSA Key Pair with Name[" + rsaname + "]");
          return (RsaKey) null;
        }
        List<IObjectHandle> rsaKeyObject1 = this.findRSAKeyObject(rsaname + "_Pub");
        List<IObjectHandle> rsaKeyObject2 = this.findRSAKeyObject(rsaname + "_Priv", IsPrivate: true);
        if (rsaKeyObject2 == null || rsaKeyObject2.Count == 0)
          return (RsaKey) null;
        attributes2.Add(CKA.CKA_MODULUS);
        foreach (IObjectAttribute attribute in this.GetAttributeList(rsaKeyObject1[0], attributes2))
        {
          CKA result;
          if (System.Enum.TryParse<CKA>(attribute.Type.ToString(), out result) && result.ToString() == "CKA_MODULUS")
            rsaKey.publicModulus = attribute.GetValueAsByteArray();
        }
        attributes1.Add(CKA.CKA_PRIVATE_EXPONENT);
        attributes1.Add(CKA.CKA_PRIME_1);
        attributes1.Add(CKA.CKA_PRIME_2);
        attributes1.Add(CKA.CKA_EXPONENT_1);
        attributes1.Add(CKA.CKA_EXPONENT_2);
        attributes1.Add(CKA.CKA_COEFFICIENT);
        attributes1.Add(CKA.CKA_PUBLIC_EXPONENT);
        foreach (IObjectAttribute attribute in this.GetAttributeList(rsaKeyObject2[0], attributes1))
        {
          CKA result;
          if (System.Enum.TryParse<CKA>(attribute.Type.ToString(), out result))
          {
            string str = result.ToString();
            if (str != null)
            {
              switch (str.Length)
              {
                case 11:
                  switch (str[10])
                  {
                    case '1':
                      if (str == "CKA_PRIME_1")
                      {
                        rsaKey.prime1 = attribute.GetValueAsByteArray();
                        break;
                      }
                      break;
                    case '2':
                      if (str == "CKA_PRIME_2")
                      {
                        rsaKey.prime2 = attribute.GetValueAsByteArray();
                        break;
                      }
                      break;
                    case 'S':
                      if (str == "CKA_MODULUS")
                      {
                        rsaKey.publicModulus = attribute.GetValueAsByteArray();
                        break;
                      }
                      break;
                  }
                  break;
                case 14:
                  switch (str[13])
                  {
                    case '1':
                      if (str == "CKA_EXPONENT_1")
                      {
                        rsaKey.exponent1 = attribute.GetValueAsByteArray();
                        break;
                      }
                      break;
                    case '2':
                      if (str == "CKA_EXPONENT_2")
                      {
                        rsaKey.exponent2 = attribute.GetValueAsByteArray();
                        break;
                      }
                      break;
                  }
                  break;
                case 15:
                  if (str == "CKA_COEFFICIENT")
                  {
                    rsaKey.coefficient = attribute.GetValueAsByteArray();
                    break;
                  }
                  break;
                case 19:
                  if (str == "CKA_PUBLIC_EXPONENT")
                  {
                    rsaKey.publicExponent = attribute.GetValueAsByteArray();
                    break;
                  }
                  break;
                case 20:
                  if (str == "CKA_PRIVATE_EXPONENT")
                  {
                    rsaKey.privateExponent = attribute.GetValueAsByteArray();
                    break;
                  }
                  break;
              }
            }
          }
        }
        KMUService.session.DestroyObject(rsaKeyObject2[0]);
        KMUService.session.DestroyObject(rsaKeyObject1[0]);
      }
      catch (AttributeValueException ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
      }
      catch (Pkcs11Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
      }
      return rsaKey;
    }

    public List<IObjectAttribute> GetAttributeList(
      IObjectHandle objHandle,
      List<CKA> attributes)
    {
      try
      {
        return KMUService.session.GetAttributeValue(objHandle, attributes);
      }
      catch (AttributeValueException ex)
      {
      }
      catch (Pkcs11Exception ex)
      {
      }
      catch (Exception ex)
      {
      }
      return (List<IObjectAttribute>) null;
    }

    public bool GenerateRSAKeyObject(
      string RSAName,
      ulong RSA_BitLength,
      byte[] PublicExponent,
      bool IsSensitive = true)
    {
      try
      {
        CKM type = CKM.CKM_RSA_PKCS;
        SingletonHSMClass.factories.MechanismFactory.Create(type);
        byte[] random = KMUService.session.GenerateRandom(20);
        List<IObjectAttribute> publicKeyAttributes = new List<IObjectAttribute>();
        publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
        publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA));
        publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false));
        publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, RSAName + "_Pub"));
        publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_ID, random));
        publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true));
        publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, true));
        publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY_RECOVER, true));
        publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, true));
        publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS_BITS, RSA_BitLength));
        publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_PUBLIC_EXPONENT, PublicExponent));
        List<IObjectAttribute> privateKeyAttributes = new List<IObjectAttribute>();
        privateKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
        publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA));
        privateKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true));
        privateKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, RSAName + "_Priv"));
        privateKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_ID, random));
        privateKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, IsSensitive));
        privateKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true));
        privateKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, true));
        privateKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN_RECOVER, true));
        privateKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, true));
        privateKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, false));
        IMechanism mechanism = SingletonHSMClass.factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
        IObjectHandle publicKeyHandle = (IObjectHandle) null;
        IObjectHandle privateKeyHandle = (IObjectHandle) null;
        KMUService.session.GenerateKeyPair(mechanism, publicKeyAttributes, privateKeyAttributes, out publicKeyHandle, out privateKeyHandle);
        if (privateKeyHandle.ObjectId > 0UL)
          return true;
      }
      catch (AttributeValueException ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
      }
      catch (Pkcs11Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
      }
      return false;
    }

    public List<IObjectHandle> findRSAKeyObject(
      string KeyName = null,
      string Subject = null,
      bool IsPrivate = false)
    {
      try
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Searching RSA Key Pair with Name[" + KeyName + "]");
        List<IObjectAttribute> attributes = new List<IObjectAttribute>();
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, IsPrivate));
        if (Subject != null)
          attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_SUBJECT, Subject));
        if (KeyName != null)
          attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, KeyName));
        List<IObjectHandle> allObjects = KMUService.session.FindAllObjects(attributes);
        if (allObjects == null)
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "NULL object return with given attribute and Name [" + KeyName + "]");
        if (allObjects.Count == 0)
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "No object Found with given attribute and Name [" + KeyName + "]");
        if (allObjects.Count > 0)
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Object Found with given attribute and Name [" + KeyName + "]");
        return allObjects;
      }
      catch (AttributeValueException ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
      }
      catch (Pkcs11Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
      }
      return (List<IObjectHandle>) null;
    }

    [WebMethod]
    public RsaKey doGenerateKeyPairReturnClearRSAKey(
      string lengthInBitsStr,
      string publicModulus)
    {
      RsaKey rsaKey = new RsaKey();
      try
      {
        rsaKey = !(publicModulus == "03") ? this.CreateRSAPAIR(lengthInBitsStr, publicModulus) : this.doGenerateKeyPairRSAKey(lengthInBitsStr, publicModulus);
      }
      catch (AttributeValueException ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
      }
      catch (Pkcs11Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
      }
      return rsaKey;
    }

    public RsaKey doGenerateKeyPairRSAKey(string lengthInBitsStr, string publicModulus)
    {
      lock (this)
      {
        byte[] byteArray = HelperFunctions.StringToByteArray(publicModulus);
        ulong uint32 = (ulong) Convert.ToUInt32(lengthInBitsStr);
        new Stopwatch().Start();
        this.Method_Name = nameof (doGenerateKeyPairRSAKey);
        try
        {
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "----------------------------------------------------------------------------------------------------------------------------");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Creating RSA Key Pair for Length[" + lengthInBitsStr + "] Exponent[" + publicModulus + "]");
          if (KMUService.session == null)
          {
            this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Session is NULL");
            KMUService.session = this._SingleInstance.instancename;
          }
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Creating Public Key Attributes");
          byte[] random = KMUService.session.GenerateRandom(20);
          List<IObjectAttribute> publicKeyAttributes = new List<IObjectAttribute>();
          publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, false));
          publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false));
          publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, SingletonHSMClass.ApplicationName));
          publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_ID, random));
          publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true));
          publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, true));
          publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY_RECOVER, true));
          publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, true));
          publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS_BITS, uint32));
          publicKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_PUBLIC_EXPONENT, byteArray));
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Created Public Key Attributes");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Creating Private Key Attributes");
          List<IObjectAttribute> privateKeyAttributes = new List<IObjectAttribute>();
          privateKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, false));
          privateKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true));
          privateKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, SingletonHSMClass.ApplicationName));
          privateKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_ID, random));
          privateKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, true));
          privateKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true));
          privateKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, true));
          privateKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN_RECOVER, true));
          privateKeyAttributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, true));
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Created Private Key Attributes");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Setting Mechanisn for RSA KEY PAIR GENERATION");
          IMechanism mechanism1 = SingletonHSMClass.factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Successful Setting Mechanisn for RSA KEY PAIR GENERATION");
          IObjectHandle publicKeyHandle = (IObjectHandle) null;
          IObjectHandle privateKeyHandle = (IObjectHandle) null;
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Calling GenerateKeyPair");
          KMUService.session.GenerateKeyPair(mechanism1, publicKeyAttributes, privateKeyAttributes, out publicKeyHandle, out privateKeyHandle);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Specify wrapping mechanism to [CKM.CKM_DES3_ECB]");
          IMechanism mechanism2 = SingletonHSMClass.factories.MechanismFactory.Create(CKM.CKM_DES3_ECB);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "After Specify wrapping mechanism [CKM.CKM_DES3_ECB]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Prepare attribute template of new key");
          List<IObjectAttribute> objectAttributeList = new List<IObjectAttribute>()
          {
            SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
            SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "LMK_MASTER_KEY"),
            SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
            SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_DES3),
            SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true),
            SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true),
            SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true),
            SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, true),
            SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, true)
          };
          IObjectHandle akeyObject = KMUService.findAKeyObject("LMK_MASTER_KEY");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "hLMKKey [" + akeyObject.ObjectId.ToString() + "]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Wraping Public Key");
          byte[] numArray1 = KMUService.session.WrapKey(mechanism2, akeyObject, publicKeyHandle);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Wraping Private Key");
          byte[] numArray2 = KMUService.session.WrapKey(mechanism2, akeyObject, privateKeyHandle);
          if (numArray1 == null || numArray2 == null)
          {
            this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception while Wrapping Key");
            throw new Exception("Fail wrapping key");
          }
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Decrypting data Private Key");
          byte[] deciphered1 = KMUService.session.Decrypt(mechanism2, akeyObject, numArray2);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Decrypted data Private Key");
          byte[] deciphered2 = KMUService.session.Decrypt(mechanism2, akeyObject, numArray1);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Encrypting data Public Key");
          KMUService.session.Encrypt(mechanism2, akeyObject, numArray2);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Encrypted data Public Key");
          KMUService.session.Encrypt(mechanism2, akeyObject, numArray1);
          byte[] numArray3 = DESCryptoLib2018.RemoveZeroTrailer(deciphered1);
          byte[] deciphered3 = DESCryptoLib2018.RemoveZeroTrailer(deciphered2);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "decrypt Private Key Bytes From Byte to Array");
          byte[] octets = ((Asn1OctetString) Asn1Sequence.GetInstance((object) Asn1Object.FromByteArray(numArray3))[2]).GetOctets();
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "OCTBYTE[" + this.util.ByteArrayToString(octets) + "]");
          RsaPrivateKeyStructure instance = RsaPrivateKeyStructure.GetInstance((object) Asn1Sequence.GetInstance((object) Asn1Object.FromByteArray(octets)));
          RsaKey rsaKey = new RsaKey();
          rsaKey.publicModulus = DESCryptoLib2018.RemoveZeroHead(instance.Modulus.ToByteArray());
          rsaKey.publicExponent = DESCryptoLib2018.RemoveZeroHead(instance.PublicExponent.ToByteArray());
          rsaKey.privateExponent = DESCryptoLib2018.RemoveZeroHead(instance.PrivateExponent.ToByteArray());
          rsaKey.prime1 = DESCryptoLib2018.RemoveZeroHead(instance.Prime1.ToByteArray());
          rsaKey.prime2 = DESCryptoLib2018.RemoveZeroHead(instance.Prime2.ToByteArray());
          rsaKey.exponent1 = DESCryptoLib2018.RemoveZeroHead(instance.Exponent1.ToByteArray());
          rsaKey.exponent2 = DESCryptoLib2018.RemoveZeroHead(instance.Exponent2.ToByteArray());
          rsaKey.coefficient = DESCryptoLib2018.RemoveZeroHead(instance.Coefficient.ToByteArray());
          rsaKey.asn1PubKey = DESCryptoLib2018.RemoveZeroHead(deciphered3);
          rsaKey.asn1PrivKey = DESCryptoLib2018.RemoveZeroHead(numArray3);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "-----------------------------------------------------------------------------------------------------------");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "rsa.publicModulus [" + this.util.ByteArrayToString(rsaKey.publicModulus) + "]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "rsa.publicExponent [" + this.util.ByteArrayToString(rsaKey.publicExponent) + "]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "rsa.privateExponent [" + this.util.ByteArrayToString(rsaKey.privateExponent) + "]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "rsa.prime1 [" + this.util.ByteArrayToString(rsaKey.prime1) + "]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "rsa.prime2 [" + this.util.ByteArrayToString(rsaKey.prime2) + "]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "rsa.exponent1 [" + this.util.ByteArrayToString(rsaKey.exponent1) + "]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "rsa.exponent2 [" + this.util.ByteArrayToString(rsaKey.exponent2) + "]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "rsa.coefficient [" + this.util.ByteArrayToString(rsaKey.coefficient) + "]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "rsa.asn1PubKey [" + this.util.ByteArrayToString(rsaKey.asn1PubKey) + "]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "rsa.asn1PrivKey [" + this.util.ByteArrayToString(rsaKey.asn1PrivKey) + "]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "-----------------------------------------------------------------------------------------------------------");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "doGenerateKeyPairReturnClearRSAKey ends");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Exiting [ " + this.Method_Name + "]");
          return rsaKey;
        }
        catch (Exception ex)
        {
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
          return (RsaKey) null;
        }
      }
    }

    public static string encryptKeyUnderLmk(string plainKey)
    {
      try
      {
        IObjectHandle akeyObject = KMUService.findAKeyObject(KMUService.LMK_KEYNAME);
        IMechanism mechanism = SingletonHSMClass.factories.MechanismFactory.Create(CKM.CKM_DES3_ECB);
        return HelperFunctions.ByteArrayToString(KMUService.session.Encrypt(mechanism, akeyObject, HelperFunctions.StringToByteArray(plainKey)));
      }
      catch (Exception ex)
      {
        int num = (int) MessageBox.Show(ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Hand);
        throw ex;
      }
    }

    public byte[] doRSASign(
      byte[] RSAPubMod,
      byte[] RSAPubExp,
      byte[] RSAPriExp,
      byte[] ClearData)
    {
      this.Method_Name = nameof (doRSASign);
      try
      {
        List<IObjectAttribute> attributes = new List<IObjectAttribute>();
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, false));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, SingletonHSMClass.ApplicationName));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, true));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, true));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN_RECOVER, true));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, true));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS_BITS, Convert.ToUInt64(ClearData.Length * 8)));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS, RSAPubMod));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_PUBLIC_EXPONENT, RSAPubExp));
        attributes.Add(SingletonHSMClass.factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE_EXPONENT, RSAPriExp));
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "CKA_LABEL [ " + SingletonHSMClass.ApplicationName + " ]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "RSAPubMod [ " + HelperFunctions.ByteArrayToString(RSAPubMod) + " ]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "RSAPubExp [ " + HelperFunctions.ByteArrayToString(RSAPubExp) + " ]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "RSAPriExp [ " + HelperFunctions.ByteArrayToString(RSAPriExp) + " ]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "ModulusBits [ " + Convert.ToUInt64(ClearData.Length * 8).ToString() + " ]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "ClearData [ " + HelperFunctions.ByteArrayToString(ClearData) + " ]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "privateKeyAttributes set");
        IObjectHandle objectHandle = KMUService.session.CreateObject(attributes);
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "CreateObject Done");
        IMechanism mechanism = SingletonHSMClass.factories.MechanismFactory.Create(CKM.CKM_RSA_X_509);
        byte[] numArray = KMUService.session.SignRecover(mechanism, objectHandle, ClearData);
        KMUService.session.DestroyObject(objectHandle);
        return numArray;
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        return (byte[]) null;
      }
    }

    [WebMethod]
    public bool createsession(int count)
    {
      try
      {
        KMUService.session = this._SingleInstance.instancename;
        count = this._SingleInstance.counter;
        return count > 0;
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        return count > 0;
      }
    }

    [WebMethod]
    public string HSM_Info()
    {
      string empty = string.Empty;
      this.Method_Name = nameof (HSM_Info);
      string str;
      try
      {
        if (KMUService.session == null || this._SingleInstance.counter == 0)
        {
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Session is NULL");
          KMUService.session = this._SingleInstance.instancename;
        }
        LogClass logWrite = this.Log_write;
        string strIpAddress = this.strIpAddress;
        string className = this.Class_Name;
        string methodName = this.Method_Name;
        ulong num = KMUService.session.SessionId;
        string message = " Session id [ " + num.ToString() + " ] ";
        logWrite.LogWrite(strIpAddress, className, methodName, "Information", message);
        ILibraryInfo info = KMUService.pkcs11.GetInfo();
        ITokenInfo tokenInfo = KMUService.slot.GetTokenInfo();
        KMUService.session.GetSessionInfo();
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "-------------------------------------------------------------------------------------");
        string[] strArray = new string[37]
        {
          KMUService.HSM_IP,
          "~",
          KMUService.HSM_PORT,
          "~",
          KMUService.HSM_USER_NAME,
          "~",
          KMUService.HSMPwd,
          "~",
          KMUService.default_slot.ToString(),
          "~",
          KMUService.Pkcs11LibraryPath,
          "~",
          info.LibraryDescription.ToString(),
          "~",
          info.LibraryVersion.ToString(),
          "~",
          info.CryptokiVersion.ToString(),
          "~",
          tokenInfo.Model.ToString(),
          "~",
          tokenInfo.Label.ToString(),
          "~",
          tokenInfo.HardwareVersion.ToString(),
          "~",
          tokenInfo.FirmwareVersion.ToString(),
          "~",
          tokenInfo.ManufacturerId.ToString(),
          "~",
          tokenInfo.SerialNumber.ToString(),
          "~",
          null,
          null,
          null,
          null,
          null,
          null,
          null
        };
        num = tokenInfo.MaxRwSessionCount;
        strArray[30] = num.ToString();
        strArray[31] = "~";
        num = tokenInfo.MaxSessionCount;
        strArray[32] = num.ToString();
        strArray[33] = "~";
        num = tokenInfo.RwSessionCount;
        strArray[34] = num.ToString();
        strArray[35] = "~";
        num = tokenInfo.SessionCount;
        strArray[36] = num.ToString();
        str = string.Concat(strArray);
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "response [" + str + "]");
        num = tokenInfo.SessionCount;
        if (Convert.ToInt32(num.ToString()) == KMUService.MaxSessionAllowed)
        {
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Session Count reached to Maximum Limit");
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Uninitializing HSM Sessions");
          this.uninitialize();
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Error", "Initializing HSM Sessions");
        }
      }
      catch (Exception ex)
      {
        this.uninitialize();
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        str = "Exception Message [" + ex.Message + "]";
      }
      return str;
    }

    [WebMethod]
    public bool uninitialize()
    {
      this.Method_Name = nameof (uninitialize);
      try
      {
        return SingletonHSMClass.HSMLogout(KMUService.session) == 1;
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "Exception StackTrace [" + ex.StackTrace + " ]");
        return SingletonHSMClass.HSMLogout(KMUService.session) == 1;
      }
    }

    [WebMethod]
    public bool Test_Service(int ThreadID)
    {
      bool ret = false;
      Thread thread = new Thread((ThreadStart) (() => ret = this.thTest_Service(ThreadID)));
      thread.Start();
      do
        ;
      while (thread.IsAlive);
      return ret;
    }

    public bool thTest_Service(int ThreadID)
    {
      Stopwatch stopwatch = new Stopwatch();
      stopwatch.Start();
      this.Method_Name = "Test_Service";
      bool flag;
      try
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "TH[" + ThreadID.ToString() + "] Count [ " + KMUService.i.ToString() + " ]");
        this.doGenerateKeyPairReturnClearRSAKey("1408", "03");
        flag = true;
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "TH[" + ThreadID.ToString() + "] Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "TH[" + ThreadID.ToString() + "] Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "TH[" + ThreadID.ToString() + "] Exception StackTrace [" + ex.StackTrace + " ]");
        flag = false;
      }
      stopwatch.Stop();
      this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "TH[" + ThreadID.ToString() + "] Time Taken [ " + stopwatch.ElapsedMilliseconds.ToString() + " ]");
      return flag;
    }

    [WebMethod]
    public string Calculate_PIN(string CardNumer, string Pin_Encryption_Key, string PinBlock)
    {
      string message1 = string.Empty;
      this.Method_Name = nameof (Calculate_PIN);
      try
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information ", "Calling Calculate_PIN_block Method");
        if (CardNumer != null && CardNumer.Length >= 16 && CardNumer.Length <= 19)
        {
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information ", CardNumer);
          CardNumer = "0000" + CardNumer.Substring(3, 12);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information ", "After Padding 0000" + CardNumer);
          CardNumer += PinBlock;
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information ", "Added Pinblock " + CardNumer);
          string message2 = this.decrypt_Key(CardNumer, Pin_Encryption_Key, true);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information ", "Decrypt " + message2);
          this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information ", message2);
          message1 = message2.Substring(16);
          if (message1.Substring(0, 1) != "0")
          {
            this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information ", message1);
            PinBlock = "InCorrect ISO format Received :" + message1;
          }
          if (message1.Substring(1, 1) != "4")
          {
            this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Incorrect Length Found[" + message1.Substring(1, 1) + "]");
            message1 = "Exception: Incorrect Length Found";
          }
          if (!int.TryParse(message1.Substring(2, 4), out int _))
          {
            this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Information", "Incorrect PIN Found[" + message1.Substring(1, 1) + "]");
            message1 = "Exception: Incorrect PIN Found";
          }
          if (message1.StartsWith("0"))
            message1 = message1.Substring(2, message1.Length - 2);
        }
      }
      catch (Exception ex)
      {
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "ex[" + ex?.ToString() + "] Exception  [" + ex.ToString() + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "ex[" + ex?.ToString() + "] Exception Message [" + ex.Message + "]");
        this.Log_write.LogWrite(this.strIpAddress, this.Class_Name, this.Method_Name, "Exception", "ex[" + ex?.ToString() + "] Exception StackTrace [" + ex.StackTrace + " ]");
      }
      return message1;
    }

    public struct KeyData
    {
      public int index { get; set; }

      public string Keyname { get; set; }

      public string KeyType { get; set; }
    }

    public struct RSAComponents
    {
      public byte[] CARSAPubModulus;
      internal byte[] IPKRSAPubModulus;
      internal byte[] ICCRSAPubModulus;
      internal byte[] ICCRSAPrivExponent;
      internal byte[] ICCRSAPrime_1;
      internal byte[] ICCRSAPrime_2;
      internal byte[] ICCRSAExp_1;
      internal byte[] ICCRSAExp_2;
      internal byte[] ICCRSACofficient;
    }
  }
}
