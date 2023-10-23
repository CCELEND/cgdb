
#include "loader_elf.h"

void map_fun_plt()
{
    unsigned long long fun_plt_addr;
    std::string fun_name;

    std::string command = std::string("objdump -d -j .plt.sec -M intel ") + fname;
    // 执行命令并将标准输出连接到文件流中
    FILE* fp = popen(command.c_str(), "r");
    if (!fp)
    {
        printf("\033[31m\033[1m[-] Popen failed!\033[0m\n");
        return;
    }

    char *result = nullptr;
    size_t len = 0;
    ssize_t read;

    while ((read = getline(&result, &len, fp)) != -1) {
        // 处理每一行输出
        if (std::string(result).find("@plt") != string::npos) 
        {
            fun_name = std::string(result).substr(19, strlen(result)-6);
            printf("%s\n", fun_name);
            fun_plt_addr = strtoul(result, nullptr, 16);
        }     
    }

    pclose(fp);   // 关闭管道
    free(result); // 释放动态分配的内存
    
}



// unsigned long long get_fun_plt(char* fun, Binary *bin)
// {
//     Section *sec;

//     for(int i = 0; i < bin->sections.size(); i++) 
//     {
//         sec = &bin->sections[i];
//         if (sec->name == ".plt.sec") {

//         }


//     }

// }


// 添加映射
    // ageMap[key1] = 30;
    // ageMap[key2] = 25;

    // // 查找映射
    // if (ageMap.find(key1) != ageMap.end()) {
    //     std::cout << key1 << "'s age is " << ageMap[key1] << " years old." << std::endl;
    // } else {
    //     std::cout << key1 << " not found in the map." << std::endl;
    // }

