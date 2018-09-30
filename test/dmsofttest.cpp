
#include "dmos.h"
#include "dmutil.h"
#include "dmtypes.h"
#include "dmformat.h"
#include "dmmd5.h"
#include "dmstrtk.hpp"

int main( int argc, char* argv[] ) {

    std::string strData = "1";

    std::string strMD5 = CDMMD5::GetMD5(strData);

    std::cout << fmt::format("{0}", strData.c_str()) << std::endl;
    std::cout << fmt::format("{0}", strMD5.c_str()) << std::endl;
    return 0;
}
