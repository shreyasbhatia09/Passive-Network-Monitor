#include "../include/optparser.h"

#include <iostream>
#include <string>
#include <vector>


int main(int argc, char **argv)
{
    optparse::OptionParser parser = optparse::OptionParser().description("Options for the application");

    parser.add_option("-i", "--interface").dest("filename")
    .help("write report to FILE");
    parser.add_option("-s", "--stringMatch").dest("stringMatch")
    .help("write report to FILE");
    parser.add_option("-r", "--fileName").dest("fileName")
    .help("write report to FILE");

    const optparse::Values options = parser.parse_args(argc, argv);
    const std::vector<std::string> args = parser.args();

    std::cout << options["filename"] << "\n";
    std::cout << options["stringName"] << "\n";
}
