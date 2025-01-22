#include<bits/stdc++.h>
using namespace std;


vector<string> split(string str, char delimiter)
{
    vector<string> tokens;
    string token;
    istringstream tokenStream(str);
    while(getline(tokenStream, token, delimiter))
    {
        tokens.push_back(token);
    }
    return tokens;
}

int maskStrToCidr(string maskStr)
{
    vector<string> octets = split(maskStr, '.');
    int cidr = 0;
    for(const string &octet: octets)
    {
        int num = stoi(octet);
        while(num > 0)
        {
            cidr += num & 1;
            num >>= 1;
        }
    }
    return cidr;
}

vector<int> ipToInt(string ipStr)
{
    vector<string> octets = split(ipStr, '.');
    vector<int> ipInt;
    for(const string &octet: octets)
    {
        ipInt.push_back(stoi(octet));
    }
    return ipInt;
}
vector<string> ipToHex(string ipStr)
{
    vector<string> octets = split(ipStr, '.'); 
    vector<string> ipHex;
    for (const string &octet : octets)
    {
        stringstream hexStream;
        hexStream << hex << uppercase << stoi(octet);
        string hexValue = hexStream.str();
        
        if (hexValue.length() == 1) 
        {
            hexValue = "0" + hexValue;
        }
        
        ipHex.push_back(hexValue);
    }
    return ipHex;
}

vector<int> cidrToMask(int cidr)
{
    vector<int> mask(4, 0);
    for(int i = 0; i < 4; i++)
    {
        if(cidr >= 8)
        {
            mask[i] = 255;
            cidr -= 8;
        }
        else
        {
            mask[i] = (256 - (1 << (8 - cidr))) & 255;
            break;
        }
    }
    return mask;
}

//integer to binary form string
string intToBinary(int num) {
    string binary;
    for (int i = 7; i >= 0; --i) {
        binary += (num & (1 << i)) ? '1' : '0'; // Check each bit from left to right
    }
    return binary;
}

// Function to convert integer vector IP to binary string
string DottedToBinary(const string &str) {
    vector<string> octets = split(str, '.'); 
    string binary;

    for (size_t i = 0; i < octets.size(); ++i) {
        int num = stoi(octets[i]);               
        string binOctet = intToBinary(num);        
        binary += binOctet;                      

        if (i < octets.size() - 1) {              
            binary += ".";
        }
    }

    return binary;
}

vector<int> calculateNetworkAddress(const vector<int> &ip, const vector<int> &mask) {
    vector<int> netAddr(4, 0);
    for (int i = 0; i < 4; i++) {
        int ipPart = ip[i];
        int maskPart = mask[i];
        int netPart = 0;

        for (int bit = 7; bit >= 0; bit--) {
            int ipBit = (ipPart >= (1 << bit)) ? 1 : 0;
            int maskBit = (maskPart >= (1 << bit)) ? 1 : 0;

            if (maskBit == 1) {
                netPart += ipBit * (1 << bit);
            }

            if (ipBit == 1) ipPart -= (1 << bit);
            if (maskBit == 1) maskPart -= (1 << bit);
        }
        netAddr[i] = netPart;
    }
    return netAddr;
}

vector<int> calculateBroadcastAddress(const vector<int> &ip, const vector<int> &mask) {
    vector<int> broadcastAddr(4, 0);
    for (int i = 0; i < 4; i++) {
        int ipPart = ip[i];
        int maskPart = mask[i];
        int broadcastPart = 0;

        for (int bit = 7; bit >= 0; bit--) {
            int ipBit = (ipPart >= (1 << bit)) ? 1 : 0;
            int maskBit = (maskPart >= (1 << bit)) ? 1 : 0;

            if (maskBit == 1) {
                broadcastPart += ipBit * (1 << bit);
            } else {
                broadcastPart += (1 << bit);
            }

            if (ipBit == 1) ipPart -= (1 << bit);
            if (maskBit == 1) maskPart -= (1 << bit);
        }
        broadcastAddr[i] = broadcastPart;
    }
    return broadcastAddr;
}
vector<int> calculateWildcardMask(const vector<int> &mask) {
    vector<int> wildcardMask(4, 0);
    for (int i = 0; i < 4; i++) {
        int maskPart = mask[i];
        int wildcardPart = 0;

        for (int bit = 7; bit >= 0; bit--) {
            int maskBit = (maskPart >= (1 << bit)) ? 1 : 0;

            // Invert the mask bit to calculate wildcard bit
            int wildcardBit = (maskBit == 1) ? 0 : 1;

            wildcardPart += wildcardBit * (1 << bit);

            if (maskBit == 1) {
                maskPart -= (1 << bit);
            }
        }
        wildcardMask[i] = wildcardPart;
    }
    return wildcardMask;
}

int calculateNumberOfHosts(int cidr) {
    int h = 32 - cidr; 
    int host = 1;     
    
    for (int i = 1; i <= h; i++) {
        host *= 2;     
    }
    
    return host;
}

string getIPClass(const string &ip) {
    int firstOctet = 0;

    // Extract the first octet
    stringstream ss(ip);
    string octet;
    getline(ss, octet, '.');
    firstOctet = stoi(octet);

    // Determine the class based on the first octet
    if (firstOctet >= 1 && firstOctet <= 126) {
        return "Class A";
    } else if (firstOctet >= 128 && firstOctet <= 191) {
        return "Class B";
    } else if (firstOctet >= 192 && firstOctet <= 223) {
        return "Class C";
    } else if (firstOctet >= 224 && firstOctet <= 239) {
        return "Class D (Multicast)";
    } else if (firstOctet >= 240 && firstOctet <= 255) {
        return "Class E (Reserved for future use)";
    } else {
        return "Invalid IP address";
    }
}

string determineIpType(const vector<int> &ip) {
    // Check if the IP is in the private range
    if (ip[0] == 10) {
        return "Private";
    } else if (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) {
        return "Private";
    } else if (ip[0] == 192 && ip[1] == 168) {
        return "Private";
    } else if (ip[0] == 127) {
        return "Loopback (Reserved)";
    } else if (ip[0] >= 224) {
        return "Reserved or Multicast";
    } else {
        return "Public";
    }
}


// Function to display an IP address
void displayIPAddress(const vector<int>& ip) {
    cout << ip[0] << "." << ip[1] << "." << ip[2] << "." << ip[3];
}

// Function to validate IP address format (xxx.xxx.xxx.xxx)
bool isValidIP(const string& ip) {
    regex ipPattern(R"((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}))");
    smatch match;

    if (regex_match(ip, match, ipPattern)) {
        // Validate each part of the IP is between 0 and 255
        for (size_t i = 1; i < match.size(); ++i) {
            int part = stoi(match[i].str());
            if (part < 0 || part > 255) {
                return false;
            }
        }
        return true;
    }
    return false;
}

string ipToInAddrArpa(const string &ipStr) {
    string octets[4]; 
    int octetIndex = 0; 

    for (char ch : ipStr) {
        if (ch == '.') {
            ++octetIndex;
            if (octetIndex > 3) {
                return ""; 
            }
        } else if (isdigit(ch)) {
            octets[octetIndex] += ch;
        } else {
            return ""; 
        }
    }

    if (octetIndex != 3) {
        return ""; 
    }
    for (int i = 0; i < 4; ++i) {
        if (octets[i].empty() || stoi(octets[i]) > 255) {
            return ""; 
        }
    }
    string inAddrArpa = octets[3] + "." + octets[2] + "." + octets[1] + "." + octets[0] + ".in-addr.arpa";
    return inAddrArpa;
}

// Function to convert an IPv4 address to an IPv4-mapped IPv6 address
string ipv4ToIpv4Mapped(const string &ipv4) {
    vector<string> octets = split(ipv4, '.');
    if (octets.size() != 4) {
        return "Invalid IPv4 address";
    }

    stringstream ipv6Stream;
    ipv6Stream << "::ffff:";
    for (size_t i = 0; i < octets.size(); ++i) {
        int octet = stoi(octets[i]);
        if (octet < 0 || octet > 255) {
            return "Invalid IPv4 address"; 
        }

        
        ipv6Stream << hex << octet;
        if (i == 1) ipv6Stream << ":";
    }

    return ipv6Stream.str();
}

// Function to calculate and print all subnets
void calculateSubnets(const vector<int>& baseIP, int cidr) {
    int totalIPs = pow(2, 32 - cidr); // Total IPs in the subnet
    int increment = totalIPs;         // Increment for each subnet
    int subnets = 256 / totalIPs;     // Total subnets in the /24 block

    vector<int> currentIP = baseIP;

    cout << "Network Address\tUsable Host Range\t\tBroadcast Address\n";
    cout << "------------------------------------------------------------\n";

    for (int i = 0; i < subnets; ++i) {
        vector<int> networkAddress = currentIP;

        // First usable host
        vector<int> firstUsable = currentIP;
        firstUsable[3] += 1;

        // Last usable host
        vector<int> lastUsable = currentIP;
        lastUsable[3] += totalIPs - 2;

        // Broadcast address
        vector<int> broadcastAddress = currentIP;
        broadcastAddress[3] += totalIPs - 1;

        // Print the subnet details
        displayIPAddress(networkAddress);
        cout << "\t";
        displayIPAddress(firstUsable);
        cout << " - ";
        displayIPAddress(lastUsable);
        cout << "\t";
        displayIPAddress(broadcastAddress);
        cout << endl;

        // Move to the next subnet
        currentIP[3] += increment;

        // Handle overflow for next subnet
        for (int j = 3; j >= 0; --j) {
            if (currentIP[j] > 255) {
                currentIP[j] = 0;
                if (j > 0) {
                    currentIP[j - 1]++;
                }
            }
        }
    }
}

void displayN_R_B() {
    string input;
    cout << "Enter IP address with CIDR notation (e.g., 118.179.64.0/30): ";
    cin >> input;

    // Parse the input IP and CIDR
    size_t slashPos = input.find('/');
    if (slashPos == string::npos) {
        cout << "Error: CIDR notation must include '/' followed by the CIDR value (e.g., 118.179.64.0/30)." << endl;
        return;
    }

    string ipPart = input.substr(0, slashPos);
    string cidrPart = input.substr(slashPos + 1);

    // Validate CIDR part
    if (cidrPart.empty() || !all_of(cidrPart.begin(), cidrPart.end(), ::isdigit)) {
        cout << "Error: CIDR part must be a number." << endl;
        return;
    }
    int cidr = stoi(cidrPart);
    
    // Validate CIDR range
    if (cidr < 0 || cidr > 30) {
        cout << "Error: Invalid CIDR value. Please enter a value between 0 and 30." << endl;
        return;
    }

    // Validate IP address format
    if (!isValidIP(ipPart)) {
        cout << "Error: Invalid IP address format." << endl;
        return;
    }

    // Parse the IP address into vector
    vector<int> baseIP(4);
    sscanf(ipPart.c_str(), "%d.%d.%d.%d", &baseIP[0], &baseIP[1], &baseIP[2], &baseIP[3]);

    // Calculate and display all subnets
    calculateSubnets(baseIP, cidr);
}


class EfficiencySubnetMaskDivide {
public:
    bool isValidIP(const string& ip) {
        vector<int> ipParts(4, 0);
        stringstream ss(ip);
        string part;
        int i = 0;

        while (getline(ss, part, '.') && i < 4) {
            try {
                ipParts[i++] = stoi(part);
            } catch (...) {
                return false;
            }
        }

        for (int j = 0; j < 4; j++) {
            if (ipParts[j] < 0 || ipParts[j] > 255) {
                return false;
            }
        }

        return true;
    }

    int calculatePrefix(int neededIPs) {
        int totalIPs = neededIPs + 2;
        return 32 - ceil(log2(totalIPs)); 
    }

    string calculateBroadcastAddress(string networkAddress, int blockSize) {
        size_t pos = networkAddress.find_last_of('.'); 
        string ipPrefix = networkAddress.substr(0, pos + 1); 
        int lastOctet = stoi(networkAddress.substr(pos + 1)); 
        int broadcast = lastOctet + blockSize - 1;
        
        if (broadcast > 255) {
            return "Unavailable";
        }
        return ipPrefix + to_string(broadcast); 
    }

    pair<string, string> calculateHostRange(string networkAddress, int blockSize) {
        size_t pos = networkAddress.find_last_of('.'); 
        string ipPrefix = networkAddress.substr(0, pos + 1); 
        int firstHost = stoi(networkAddress.substr(pos + 1)) + 1; 
        int lastHost = firstHost + blockSize - 3; 
        return {ipPrefix + to_string(firstHost), ipPrefix + to_string(lastHost)};
    }

    void SubnetMaskDivide() {
        string baseIP;
        int baseCIDR;
        
        cout << "Enter the base IP address with CIDR (e.g., 192.168.23.0/24): ";
        cin >> baseIP;

        size_t cidrPos = baseIP.find('/');
        string ipAddress = baseIP.substr(0, cidrPos);
        if (!isValidIP(ipAddress)) {
            cout << "Unavailable: The provided IP address is invalid." << endl;
            return;
        }

        baseCIDR = stoi(baseIP.substr(cidrPos + 1));
        
        int numCustomers;
        
        cout << "Enter the number of customers: ";
        cin >> numCustomers;

        int customerNeeds[numCustomers];
        
        cout << "Enter the number of IPs needed for each customer:\n";
        for (int i = 0; i < numCustomers; i++) {
            cout << "Customer " << i + 1 << ": ";
            cin >> customerNeeds[i];
        }

        int baseOffset = 0;

        cout << "\nSubnet Allocation:\n";
        cout << "--------------------------------------------------------------------------------------\n";
        cout << left << setw(10) << "Customer" << setw(20) << "Network Address" 
             << setw(35) << "Usable Host Range" << "Broadcast Address\n";
        cout << "--------------------------------------------------------------------------------------\n";

        for (int i = 0; i < numCustomers; i++) {
            int neededIPs = customerNeeds[i];                
            int prefix = calculatePrefix(neededIPs);          
            int blockSize = 1 << (32 - prefix);

            string networkAddress = calculateNetworkAddress(baseIP, baseOffset);

            if (networkAddress.empty()) {
                cout << "Error: IP address exceeds valid range." << endl;
                continue;
            }

            string broadcastAddress = calculateBroadcastAddress(networkAddress, blockSize);
            pair<string, string> hostRange = calculateHostRange(networkAddress, blockSize);

            if (broadcastAddress == "Unavailable") {
                cout << left << setw(10) << "Customer " + to_string(i + 1)<<":" 
                     << setw(20) << networkAddress + "/" + to_string(prefix)
                     << setw(35) << hostRange.first + " - " + hostRange.second
                     << "Unavailable (broadcast exceeds range)" << endl;
                baseOffset += blockSize;
                continue;
            }

            cout << left << setw(10) << "Customer " + to_string(i + 1) <<":"
                 << setw(20) << networkAddress + "/" + to_string(prefix)
                 << setw(35) << hostRange.first + " - " + hostRange.second
                 << broadcastAddress << "\n";

            baseOffset += blockSize;
        }

        cout << "--------------------------------------------------------------------------------------\n";
    }

    private:
    string calculateNetworkAddress(string baseIP, int offset) {
        vector<int> ipParts(4, 0);
        size_t pos = 0;
        int octetIndex = 0;

        while ((pos = baseIP.find('.')) != string::npos) {
            ipParts[octetIndex++] = stoi(baseIP.substr(0, pos));
            baseIP.erase(0, pos + 1);
        }
        ipParts[3] = stoi(baseIP);

        ipParts[3] += offset;

        for (int i = 3; i >= 0; i--) {
            if (ipParts[i] > 255) {
                if (i > 0) {
                    ipParts[i - 1] += ipParts[i] / 256;
                    ipParts[i] %= 256;
                } else {
                    return "";
                }
            }
        }
        return to_string(ipParts[0]) + "." + to_string(ipParts[1]) + "." + to_string(ipParts[2]) + "." + to_string(ipParts[3]);
    }
};

void displayOutput(string ipStr, string maskStr)
{
    int cidr = maskStrToCidr(maskStr);
    vector<int> ipInt = ipToInt(ipStr);
    vector<int> maskInt = cidrToMask(cidr);
    vector<string> ipHexa=ipToHex(ipStr);
    vector<string> maskHexa=ipToHex(maskStr);
    string inaddrArpa=ipToInAddrArpa(ipStr);
    vector<int> networkAddress = calculateNetworkAddress(ipInt, maskInt);
    vector<int> broadcastAddress = calculateBroadcastAddress(ipInt, maskInt);
    vector<int> wildcardAddress = calculateWildcardMask(maskInt);
    int host = calculateNumberOfHosts(cidr);

    cout<<endl<<endl;
    cout<<"-----------------------------------------------------------------"<<endl;
    cout << "IP Address  : " << ipStr << endl;
    cout << "Subnet Mask : " << maskStr << endl;
    cout << "IP Address with CIDR Notation: " << ipStr << "/" << cidr << endl;
    cout<<"Network Address :";
    for (int i = 0; i < networkAddress.size(); i++) {
        cout << networkAddress[i];
        if (i < networkAddress.size() - 1) {
            cout << ".";
        }
        else cout<<endl;
    }
    cout<<"Broadcast Address :";
    for (int i = 0; i < broadcastAddress.size(); i++) {
        cout << broadcastAddress[i];
        if (i < broadcastAddress.size() - 1) {
            cout << ".";
        }
        else cout<<endl;
    }
    cout<<"Number of total Host :"<<host<<endl;
    cout<<"Number of total useable host :"<<host-2<<endl;

    cout<<"-------------------------------------------------------"<<endl<<endl;
    cout<<"IP type: "<<determineIpType(ipInt)<<endl;
    string ipClass=getIPClass(ipStr);
    cout<<"Ip Class Type: "<<ipClass<<endl;
    cout<<"WildCard Mask Address :";
    for (int i = 0; i < wildcardAddress.size(); i++) {
        cout << wildcardAddress[i];
        if (i < wildcardAddress.size() - 1) {
            cout << ".";
        }
        else cout<<endl;
    }
    cout<<"In-addr.arpa :"<<inaddrArpa<<endl;
    cout<<"IPv4 Mapped Address: "<<ipv4ToIpv4Mapped(ipStr)<<endl;
    cout<<"-------------------------------------------------------------"<<endl<<endl;

    cout << "IP address in Binary: " << DottedToBinary(ipStr) << endl;
    cout << "Subnet Mask in Binary: " << DottedToBinary(maskStr) << endl;
    cout<<"IP address in Hexadecimal: ";
    for (int i = 0; i < ipHexa.size(); i++) {
        cout << ipHexa[i];
        if (i < ipHexa.size() - 1) {
            cout << ".";
        }
        else cout<<endl;
    }
    cout<<"Subnet mask in Hexadecimal: ";
    for (int i = 0; i < maskHexa.size(); i++) {
        cout << maskHexa[i];
        if (i < maskHexa.size() - 1) {
            cout << ".";
        }
        else cout<<endl;
    }
    cout << "IP Address as Decimal: ";
    for(int num: ipInt)
    {
        cout << num << " ";
    }
    cout << endl;
    cout << "Subnet Mask as Decimal: ";
    for(int num: maskInt)
    {
        cout << num << " ";
    }
    cout << endl;
    cout<<"----------------------------------------"<<endl;
    EfficiencySubnetMaskDivide subnetAllocator;
    subnetAllocator.SubnetMaskDivide();
    displayN_R_B();

}

int main()
{
    string ipStr;
    string maskStr;

    cout << "Enter IP address (e.g., 192.168.100.0): ";
    cin >> ipStr;
    cout << "Enter Subnet Mask (e.g., 255.255.255.128): ";
    cin >> maskStr;

    displayOutput(ipStr, maskStr);

    return 0;
}
