#include <fstream>
#include <string>

using namespace std;


ifstream::pos_type filesize(const string& filename)
{
    return ifstream(filename, ios::ate | ios::binary).tellg(); 
}
