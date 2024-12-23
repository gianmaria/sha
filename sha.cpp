#include <iostream>
#include <fstream>
#include <string>
#include <string_view>
#include <filesystem>
#include <vector>

using std::cout;
using std::cerr;
using std::endl;
using std::string;
using std::string_view;
using std::ifstream;
using std::ofstream;
using std::vector;

namespace fs = std::filesystem;

#include "win_cpp_crypt.h"

int calsulate_sha256(const string& input_file)
{
    ifstream ifs(input_file, std::ios::binary);

    if (!ifs)
    {
        cerr << "Error: cannot open input file '" << input_file << "'" << endl;
        return 1;
    }

    auto input_file_size = fs::file_size(input_file);

    vector<char> input_file_content(input_file_size);

    ifs.read(input_file_content.data(), input_file_content.size());

    if (not ifs.good())
    {
        cerr << "Error: only " << ifs.gcount() << " bytes could be read from " << input_file << endl;
        return 1;
    }

    auto sha = WinCppCrypt::SHA256::generate(
        reinterpret_cast<PUCHAR>(input_file_content.data()),
        input_file_content.size()
    );

    if (sha.hasError())
    {
        cerr << "Error: " << sha.error().what() << endl;
        return 1;
    }

    cout << input_file << ": " << WinCppCrypt::Util::toHexString(sha.unwrap()) << endl;

    return 0;
}

int main(int argc, char* argv[])
{
    try
    {
        if (argc != 2)
        {
            cerr << "Usage:" << endl
                << "    sha <input_file>" << endl;

            return 1;
        }

        return calsulate_sha256(argv[1]);

    }
    catch (const std::exception& e)
    {
        cerr << "Error: " << e.what() << '\n';
        return 1;
    }

    return 0;
}
