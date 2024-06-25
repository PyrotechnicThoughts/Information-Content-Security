#ifndef HASH_TABLE_H
#define HASH_TABLE_H

// #define MAIN_HASH_TABLE

#define INITIAL_SIZE 10000
#define LOAD_FACTOR 0.75

#define MAX_LINE_LENGTH 4096
#define SSLKEYLOGFILE "/home/sunyafeng/sslkey.log"

// 定义哈希表结构
typedef struct Entry {
    char *key;
    char *value;
    struct Entry *next;
} Entry;

typedef struct {
    Entry **entries;
    int size;
    int count;
} HashTable;

// 创建哈希表
HashTable* create_table(int size);

// 释放哈希表
void free_table(HashTable *table);

// 插入键值对
void insert_entry(HashTable *table, const char *key, const char *value);

// 查找键值对
char* search_entry(HashTable *table, const char *key);

// 删除键值对
void delete_entry(HashTable *table, const char *key);

HashTable *get_dict_from_sslkeylog();

#endif
