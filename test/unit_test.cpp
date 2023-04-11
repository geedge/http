#include <gtest/gtest.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "http.h"

TEST(HTTPUnitTest, url_decode)
{
	const char *input = "%A9%E4%B8%8B%E8%B6%B3%E7%90%83%2CRB%E8%8E%B1%E6%AF%94%E9%94%A1%2C%E5%BC%97%E8%B5%96%E5%A0%A1%2C%E6%96%AF%E6%89%98%E5%85%8B%E5%9F%8E%2C%E4%BC%AF%E6%81%A9%E8%8C%85%E6%96%AF%2C%E9%97%A8%E5%85%B4%2C%E8%90%A8%E7%B4%A2%E6%B4%9B%2C%E8%B6%B3%E7%90%83%2C%E7%9A%87%E5%AE%B6%E7%A4%BE%E4%BC%9A%2C%E8%8B%B1%E8%B6%85%2C%E6%9B%BC%E5%BD%BB%E6%96%AF%E7%89%B9%E8%81%94%2C%E5%9F%83%E7%93%A6%E5%B0%94%2C%E8%A5%BF%E4%B9%99%2C%E6%B3%95%E5%85%B0%E5%85%8B%E7%A6%8F%2C%E6%8B%89%E6%96%AF%E5%B8%95%E5%B0%94%E9%A9%AC%E6%96%AF%2C%E6%B2%99%E5%B0%94%E5%85%8B%2C%E7%9A%87%E5%AE%B6%E9%A9%AC%E5%BE%B7%E9%87%8C%2C%E7%83%AD%E9%82%A3%E4%BA%9A%2C%E7%BE%8E%E5%9B%A0%E8%8C%A8%2C%E5%B7%B4%E8%90%A8%2C%E8%8E%B1%E6%AF%94%E9%94%A1%E7%BA%A2%E7%89%9B%2C%E6%96%AF%E5%9B%BE%E5%8A%A0%E7%89%B9%2CCBA%2C%E5%A5%A5%E8%90%A8%E8%8B%8F%E7%BA%B3%2C%E6%8B%9C%E4%BB%81%E6%85%95%E5%B0%BC%E9%BB%91%2C%E8%B5%AB%E7%BD%97%E7%BA%B3%2C%E6%81%A9%E6%B3%A2%E5%88%A9%2C%E6%AF%95%E5%B0%94%E5%B7%B4%E9%84%82%2C%E5%A1%9E%E5%B0%94%E5%A1%94%2C%E7%9A%87%E5%AE%B6%E8%B4%9D%E8%92%82%E6%96%AF%2C%E6%B2%8";
    int len = strlen(input);
    char *output = (char*)calloc(strlen(input)+1, 1);
    memcpy(output, input, strlen(input));

	http_url_decode(output, &len);
	
	EXPECT_EQ(len, 347);
	EXPECT_EQ(strlen(output), 346);
	
	free(output);

}

int main(int argc, char ** argv)
{
	int ret=0;
	::testing::InitGoogleTest(&argc, argv);
	ret=RUN_ALL_TESTS();
	return ret;
}
