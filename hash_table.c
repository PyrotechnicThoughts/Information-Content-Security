#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hash_table.h"

// 哈希函数（DJB2）
unsigned int hash(const char *key)
{
    unsigned long hash = 5381;
    int c;
    while ((c = *key++))
    {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

// 创建条目
Entry *create_entry(const char *key, const char *value)
{
    Entry *entry = (Entry *)malloc(sizeof(Entry));
    entry->key = strdup(key);
    entry->value = strdup(value);
    entry->next = NULL;
    return entry;
}

// 创建哈希表
HashTable *create_table(int size)
{
    HashTable *table = (HashTable *)malloc(sizeof(HashTable));
    table->entries = (Entry **)malloc(sizeof(Entry *) * size);
    for (int i = 0; i < size; i++)
    {
        table->entries[i] = NULL;
    }
    table->size = size;
    table->count = 0;
    return table;
}

// 释放条目
void free_entry(Entry *entry)
{
    free(entry->key);
    free(entry->value);
    free(entry);
}

// 释放哈希表
void free_table(HashTable *table)
{
    if (table == NULL)
        return;

    for (int i = 0; i < table->size; i++)
    {
        Entry *entry = table->entries[i];
        while (entry != NULL)
        {
            Entry *next = entry->next;
            free_entry(entry);
            entry = next;
        }
    }
    free(table->entries);
    free(table);
}

// 调整哈希表大小
void resize_table(HashTable *table)
{
    int new_size = table->size * 2;
    Entry **new_entries = (Entry **)malloc(sizeof(Entry *) * new_size);
    for (int i = 0; i < new_size; i++)
    {
        new_entries[i] = NULL;
    }

    for (int i = 0; i < table->size; i++)
    {
        Entry *entry = table->entries[i];
        while (entry != NULL)
        {
            Entry *next = entry->next;
            unsigned int slot = hash(entry->key) % new_size;
            entry->next = new_entries[slot];
            new_entries[slot] = entry;
            entry = next;
        }
    }

    free(table->entries);
    table->entries = new_entries;
    table->size = new_size;
}

// 插入键值对
void insert_entry(HashTable *table, const char *key, const char *value)
{
    if ((double)table->count / table->size > LOAD_FACTOR)
    {
        resize_table(table);
    }

    unsigned int slot = hash(key) % table->size;
    Entry *entry = table->entries[slot];

    // 若插槽为空，直接插入
    if (entry == NULL)
    {
        table->entries[slot] = create_entry(key, value);
        table->count++;
        return;
    }

    // 处理冲突
    Entry *prev;
    while (entry != NULL)
    {
        if (strcmp(entry->key, key) == 0)
        {
            free(entry->value);
            entry->value = strdup(value);
            return;
        }
        prev = entry;
        entry = entry->next;
    }
    prev->next = create_entry(key, value);
    table->count++;
}

// 查找键值对
char *search_entry(HashTable *table, const char *key)
{
    unsigned int slot = hash(key) % table->size;
    Entry *entry = table->entries[slot];

    while (entry != NULL)
    {
        if (strcmp(entry->key, key) == 0)
        {
            return entry->value;
        }
        entry = entry->next;
    }
    return NULL;
}

// 删除键值对
void delete_entry(HashTable *table, const char *key)
{
    unsigned int slot = hash(key) % table->size;
    Entry *entry = table->entries[slot];
    Entry *prev = NULL;

    while (entry != NULL && strcmp(entry->key, key) != 0)
    {
        prev = entry;
        entry = entry->next;
    }

    if (entry == NULL)
    {
        return; // 未找到键
    }

    if (prev == NULL)
    {
        table->entries[slot] = entry->next;
    }
    else
    {
        prev->next = entry->next;
    }

    free_entry(entry);
    table->count--;
}

HashTable *get_dict_from_sslkeylog()
{
    HashTable *table = create_table(INITIAL_SIZE);

    FILE *file = fopen("/home/sunyafeng/sslkey.log", "r");
    if (file == NULL)
    {
        perror("Error opening file");
        return NULL;
    }

    char line[MAX_LINE_LENGTH];

    // 逐行读取文件内容
    while (fgets(line, sizeof(line), file) != NULL)
    {
        // 解析行内容
        char key[MAX_LINE_LENGTH], value[MAX_LINE_LENGTH], discard[MAX_LINE_LENGTH];
        if (sscanf(line, "%s %s %s", discard, key, value) != 3)
        {
            // printf("Invalid line: %s", line);
            continue;
        }

        // 如果第一个字符串是CLIENT_RANDOM，则插入字典
        if (strcmp(discard, "CLIENT_RANDOM") == 0)
        {
            insert_entry(table, key, value);
        }
    }

    // 关闭文件
    fclose(file);

    return table;
}

#ifdef MAIN_HASH_TABLE

// 测试哈希表
int main()
{
    HashTable *table = create_table(INITIAL_SIZE);

    FILE *file = fopen("/home/sunyafeng/sslkey.log", "r");
    if (file == NULL)
    {
        perror("Error opening file");
        return 1;
    }

    char line[MAX_LINE_LENGTH];

    // 逐行读取文件内容
    while (fgets(line, sizeof(line), file) != NULL)
    {
        // 解析行内容
        char key[MAX_LINE_LENGTH], value[MAX_LINE_LENGTH], discard[MAX_LINE_LENGTH];
        if (sscanf(line, "%s %s %s", discard, key, value) != 3)
        {
            printf("Invalid line: %s", line);
            continue;
        }

        // 如果第一个字符串是CLIENT_RANDOM，则插入字典
        if (strcmp(discard, "CLIENT_RANDOM") == 0)
        {
            insert_entry(table, key, value);
        }
    }

    // 关闭文件
    fclose(file);

    // 打印字典内容
    printf("Dictionary:\n");
    for (int i = 0; i < table->size; i++)
    {
        Entry *entry = table->entries[i];
        while (entry != NULL)
        {
            printf("%s: %s\n", entry->key, entry->value);
            entry = entry->next;
        }
    }

    printf("%s\n", search_entry(table, "6ac7b56371ab0a94f7990636679f65cec94bdf50e4ddb6637ad81d8615a973ec"));

    free_table(table);

    // unsigned char hex_data[] = "\x48\x65\x6C\x6C\x6F"; // "Hello" 的十六进制表示
    // unsigned char str_data[sizeof(hex_data) * 2 + 1];  // 为了转换成字符串，需要考虑到每个十六进制字符占据两个字符，再加上字符串结束符 '\0'

    // // 将每个十六进制字符转换为对应的字符串形式
    // for (int i = 0; i < sizeof(hex_data) - 1; ++i)
    // {
    //     sprintf((char *)&str_data[i * 2], "%02x", hex_data[i]);
    // }

    // printf("转换后的字符串：%s\n", str_data);

    const char *str_data = "48656C6C6F"; // "Hello" 的十六进制表示
    unsigned char hex_data[sizeof(str_data) / 2];

    // 将字符串形式的十六进制转换为字节序列
    for (int i = 0; i < sizeof(str_data); i += 2)
    {
        sscanf(&str_data[i], "%2hhx", &hex_data[i / 2]);
    }

    // 输出字节序列
    printf("转换后的字节序列：\n");
    for (int i = 0; i < sizeof(hex_data); ++i)
    {
        printf("\\x%02x", hex_data[i]);
    }
    printf("\n");

    return 0;
}

#endif