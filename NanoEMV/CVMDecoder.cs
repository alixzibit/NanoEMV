using System;
using System.Text;

namespace NanoEMV
{
    public class CVMDecoder
    {
        public static string DecodeCVMList(string cvmListHex)
        {
            if (string.IsNullOrEmpty(cvmListHex) || cvmListHex.Length < 16)
            {
                throw new ArgumentException("Invalid CVM List input.");
            }

            var sb = new StringBuilder();

            for (int i = 16; i < cvmListHex.Length; i += 4)
            {
                if (i + 4 > cvmListHex.Length)
                {
                    sb.Append("Invalid or incomplete rule data\n");
                    break;
                }

                string rule = cvmListHex.Substring(i, 4);
                sb.Append(GetCVRuleControl(rule));
            }

            return sb.ToString();
        }

        private static string GetCVRuleControl(string ruleHex)
        {
            if (ruleHex.Length != 4)
            {
                throw new ArgumentException("CVM rule must be exactly 4 characters long.");
            }

            int cvmCode = 63 & Convert.ToInt32(ruleHex.Substring(0, 2), 16);
            bool applySucceedingRule = (64 & Convert.ToInt32(ruleHex.Substring(0, 2), 16)) != 0;
            int conditionCode = Convert.ToInt32(ruleHex.Substring(2, 2), 16);

            string cvmDescription = GetCVMRDescription(cvmCode);
            string conditionDescription = GetCondition(conditionCode);
            string ifUnsuccessful = applySucceedingRule ? "Apply succeeding CV Rule" : "Fail cardholder verification";

            return $"{ruleHex}\n{cvmDescription}\nCondition: {conditionDescription}\nIf unsuccessful: {ifUnsuccessful}\n\n";
        }

        private static string GetCVMRDescription(int cvmCode)
        {
            var cvmDescriptions = new Dictionary<int, string>
            {
                { 0, "Fail CVM processing" },
                { 1, "Plaintext PIN verification performed by ICC" },
                { 2, "Enciphered PIN verified online" },
                { 3, "Plaintext PIN verification performed by ICC and signature (paper)" },
                { 4, "Enciphered PIN verification performed by ICC" },
                { 5, "Enciphered PIN verification performed by ICC and signature (paper)" },
                { 6, "Facial biometric verified offline (by ICC)" },
                { 7, "Facial biometric verified online" },
                { 8, "Finger biometric verified offline (by ICC)" },
                { 9, "Finger biometric verified online" },
                { 10, "Palm biometric verified offline (by ICC)" },
                { 11, "Palm biometric verified online" },
                { 12, "Iris biometric verified offline (by ICC)" },
                { 13, "Iris biometric verified online" },
                { 14, "Voice biometric verified offline (by ICC)" },
                { 15, "Voice biometric verified online" },
                { 30, "Signature (paper)" },
                { 31, "No CVM required" },
                { 63, "No CVM Performed" }
            };

            return cvmDescriptions.TryGetValue(cvmCode, out string description) ? description : "Unknown or malformed CVM";
        }

        private static string GetCondition(int conditionCode)
        {
            var conditionDescriptions = new Dictionary<int, string>
            {
                { 0, "Always" },
                { 1, "If unattended cash" },
                { 2, "If not unattended cash and not manual cash and not purchase with cashback" },
                { 3, "If terminal supports the CVM" },
                { 4, "If manual cash" },
                { 5, "If purchase with cashback" },
                { 6, "If transaction is in the application currency and is under %X% value (implicit decimal point)" },
                { 7, "If transaction is in the application currency and is over %X% value (implicit decimal point)" },
                { 8, "If transaction is in the application currency and is under %Y% value (implicit decimal point)" },
                { 9, "If transaction is in the application currency and is over %Y% value (implicit decimal point)" }
            };

            return conditionDescriptions.TryGetValue(conditionCode, out string description) ? description : "Unknown rule or malformed CVM";
        }
    }
}
