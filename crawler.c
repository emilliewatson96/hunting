/*
 * C-Based Web Crawler with Depth-First Traversal
 * 
 * Features:
 * - Seed input: domains, subdomains, IPs, CIDR ranges
 * - Depth-first crawl strategy
 * - User-Agent rotation for anti-bot evasion
 * - Cookie handling via libcurl
 * - URL parameter extraction
 * - Asset extraction (images, scripts, stylesheets)
 * - MySQL storage of crawled data
 * - External link filtering
 * - Static compilation support
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/* libcurl for HTTP requests */
#include <curl/curl.h>

/* libxml2 for HTML parsing */
#include <libxml/HTMLparser.h>
#include <libxml/xpath.h>
#include <libxml/tree.h>

/* MySQL client library (MariaDB) */
#include <mysql.h>

/* zlib for compression */
#include <zlib.h>

/* ============== Configuration Constants ============== */
#define MAX_URL_LENGTH 2048
#define MAX_HOSTS 10000
#define MAX_VISITED_URLS 100000
#define MAX_DEPTH 10
#define REQUEST_DELAY_MS 500
#define MAX_USER_AGENTS 20
#define MAX_PARAMS_PER_URL 50
#define MAX_ASSETS_PER_PAGE 100

/* ============== Data Structures ============== */

/* URL components structure */
typedef struct {
    char scheme[16];
    char host[256];
    char path[1024];
    char query[1024];
    int port;
} URLComponents;

/* URL parameter structure */
typedef struct {
    char name[256];
    char value[512];
} URLParam;

/* Asset structure */
typedef struct {
    char url[MAX_URL_LENGTH];
    char type[32]; /* image, script, stylesheet, etc. */
} Asset;

/* Crawled page record */
typedef struct {
    char full_url[MAX_URL_LENGTH];
    char host[256];
    char path[1024];
    char query[1024];
    int status_code;
    long content_length;
    char content_type[128];
    char http_date[64];
    int depth;
    time_t crawled_at;
} CrawledPage;

/* Frontier stack for DFS */
typedef struct {
    char **urls;
    int *depths;
    int top;
    int capacity;
} CrawlStack;

/* Visited URLs set (simple hash table) */
typedef struct {
    char **urls;
    int count;
    int capacity;
} VisitedSet;

/* Global state */
typedef struct {
    CrawlStack stack;
    VisitedSet visited;
    MYSQL *db_conn;
    CURL *curl;
    char target_host[256];
    char **allowed_hosts;
    int allowed_hosts_count;
    char **blacklist;
    int blacklist_count;
    char user_agents[MAX_USER_AGENTS][512];
    int user_agent_count;
    int max_depth;
    int pages_crawled;
    int max_pages;
} CrawlerState;

/* ============== Blacklist Domains ============== */
static const char *DEFAULT_BLACKLIST[] = {
    "google.com",
    "youtube.com",
    "instagram.com",
    "facebook.com",
    "twitter.com",
    "linkedin.com",
    "amazon.com",
    "microsoft.com",
    "apple.com",
    "cloudflare.com",
    "googletagmanager.com",
    "google-analytics.com",
    "doubleclick.net",
    NULL
};

/* ============== User Agents for Rotation ============== */
static const char *USER_AGENTS[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
    NULL
};

/* ============== Function Prototypes ============== */
int init_crawler(CrawlerState *state);
void cleanup_crawler(CrawlerState *state);
int expand_cidr(const char *cidr, char **hosts, int *count);
int resolve_hostname(const char *hostname, char *ip);
int parse_url(const char *url, URLComponents *comp);
int build_url(URLComponents *comp, char *result);
int is_visited(CrawlerState *state, const char *url);
void mark_visited(CrawlerState *state, const char *url);
int is_allowed_host(CrawlerState *state, const char *host);
int is_blacklisted(CrawlerState *state, const char *host);
void push_url(CrawlerState *state, const char *url, int depth);
char *pop_url(CrawlerState *state, int *depth);
int fetch_page(CrawlerState *state, const char *url, char **content, long *content_len, 
               int *status_code, char *content_type, char *http_date);
int extract_links(CrawlerState *state, const char *html, const char *base_url, int depth);
int extract_assets(CrawlerState *state, const char *html, const char *base_url);
int extract_url_params(const char *url, URLParam *params, int *count);
int insert_page_to_db(CrawlerState *state, CrawledPage *page);
int insert_params_to_db(CrawlerState *state, int page_id, URLParam *params, int count);
int insert_assets_to_db(CrawlerState *state, int page_id, Asset *assets, int count);
void crawl(CrawlerState *state);
int load_seeds(const char *filename, char **seeds, int *count);
void print_usage(const char *prog);

/* ============== Utility Functions ============== */

/* Sleep in milliseconds */
void sleep_ms(int ms) {
    usleep(ms * 1000);
}

/* Generate random number in range */
int random_range(int min, int max) {
    return min + rand() % (max - min + 1);
}

/* String helper: trim whitespace */
char *trim(char *str) {
    char *end;
    while(isspace((unsigned char)*str)) str++;
    if(*str == 0) return str;
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

/* String helper: escape for SQL */
char *sql_escape(MYSQL *conn, const char *src, char *dest, size_t dest_size) {
    if (!conn || !src) {
        if (dest && dest_size > 0) dest[0] = '\0';
        return dest;
    }
    mysql_real_escape_string(conn, dest, src, strlen(src));
    return dest;
}

/* ============== CIDR Expansion ============== */

/* Parse IP address to integer */
unsigned int ip_to_int(const char *ip) {
    unsigned int b1, b2, b3, b4;
    if (sscanf(ip, "%u.%u.%u.%u", &b1, &b2, &b3, &b4) != 4) {
        return 0;
    }
    return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
}

/* Convert integer to IP address string */
void int_to_ip(unsigned int ip, char *result) {
    sprintf(result, "%u.%u.%u.%u",
            (ip >> 24) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF,
            ip & 0xFF);
}

/* Expand CIDR notation to individual IPs */
int expand_cidr(const char *cidr, char **hosts, int *count) {
    char ip_part[64];
    int prefix_len;
    unsigned int ip_int, network, broadcast;
    unsigned int i;
    
    *count = 0;
    
    /* Find the / separator */
    char *slash = strchr(cidr, '/');
    if (!slash) {
        /* Not a CIDR, treat as single IP */
        hosts[*count] = strdup(cidr);
        (*count)++;
        return 1;
    }
    
    /* Extract IP and prefix length */
    int ip_len = slash - cidr;
    if (ip_len >= sizeof(ip_part)) ip_len = sizeof(ip_part) - 1;
    strncpy(ip_part, cidr, ip_len);
    ip_part[ip_len] = '\0';
    prefix_len = atoi(slash + 1);
    
    if (prefix_len < 0 || prefix_len > 32) {
        fprintf(stderr, "Invalid CIDR prefix: %s\n", cidr);
        return 0;
    }
    
    ip_int = ip_to_int(ip_part);
    if (ip_int == 0) {
        fprintf(stderr, "Invalid IP in CIDR: %s\n", cidr);
        return 0;
    }
    
    /* Calculate network and broadcast addresses */
    unsigned int mask = (prefix_len == 0) ? 0 : (~0U << (32 - prefix_len));
    network = ip_int & mask;
    broadcast = network | (~mask);
    
    /* Generate all IPs in range (skip network and broadcast for /31 and larger) */
    for (i = network; i <= broadcast && *count < MAX_HOSTS; i++) {
        /* Skip network and broadcast addresses for subnets larger than /31 */
        if (prefix_len < 31) {
            if (i == network || i == broadcast) continue;
        }
        hosts[*count] = malloc(16);
        int_to_ip(i, hosts[*count]);
        (*count)++;
    }
    
    return *count;
}

/* ============== DNS Resolution ============== */

/* Resolve hostname to IP address */
int resolve_hostname(const char *hostname, char *ip) {
    struct hostent *he;
    struct in_addr **addr_list;
    struct in_addr addr;
    
    /* First check if it's already an IP */
    if (inet_aton(hostname, &addr)) {
        strcpy(ip, hostname);
        return 1;
    }
    
    he = gethostbyname(hostname);
    if (he == NULL) {
        return 0;
    }
    
    addr_list = (struct in_addr **)he->h_addr_list;
    if (addr_list[0]) {
        strcpy(ip, inet_ntoa(*addr_list[0]));
        return 1;
    }
    
    return 0;
}

/* ============== URL Parsing ============== */

/* Parse URL into components */
int parse_url(const char *url, URLComponents *comp) {
    char temp[MAX_URL_LENGTH];
    char *ptr, *start;
    
    memset(comp, 0, sizeof(URLComponents));
    comp->port = 80; /* default HTTP port */
    strcpy(comp->scheme, "http");
    
    if (!url || strlen(url) == 0) return 0;
    
    strncpy(temp, url, MAX_URL_LENGTH - 1);
    temp[MAX_URL_LENGTH - 1] = '\0';
    
    /* Extract scheme */
    ptr = strstr(temp, "://");
    if (ptr) {
        *ptr = '\0';
        strncpy(comp->scheme, temp, sizeof(comp->scheme) - 1);
        start = ptr + 3;
        
        /* Set default port based on scheme */
        if (strcmp(comp->scheme, "https") == 0) {
            comp->port = 443;
        }
    } else {
        start = temp;
    }
    
    /* Extract host (and optional port) */
    ptr = strchr(start, '/');
    if (ptr) {
        *ptr = '\0';
        strncpy(comp->path, ptr + 1, sizeof(comp->path) - 1);
    } else {
        strcpy(comp->path, "/");
    }
    
    /* Parse host and port */
    char *colon = strchr(start, ':');
    if (colon) {
        *colon = '\0';
        comp->port = atoi(colon + 1);
    }
    
    strncpy(comp->host, start, sizeof(comp->host) - 1);
    
    /* Extract query string from path */
    ptr = strchr(comp->path, '?');
    if (ptr) {
        *ptr = '\0';
        strncpy(comp->query, ptr + 1, sizeof(comp->query) - 1);
    }
    
    /* Ensure path starts with / */
    if (comp->path[0] != '/') {
        memmove(comp->path + 1, comp->path, strlen(comp->path) + 1);
        comp->path[0] = '/';
    }
    
    return 1;
}

/* Build URL from components */
int build_url(URLComponents *comp, char *result) {
    if (strlen(comp->query) > 0) {
        sprintf(result, "%s://%s:%d%s?%s", 
                comp->scheme, comp->host, comp->port, comp->path, comp->query);
    } else {
        sprintf(result, "%s://%s:%d%s", 
                comp->scheme, comp->host, comp->port, comp->path);
    }
    return 1;
}

/* Normalize URL for comparison */
void normalize_url(const char *url, char *normalized) {
    URLComponents comp;
    if (parse_url(url, &comp)) {
        /* Lowercase host */
        for (int i = 0; comp.host[i]; i++) {
            comp.host[i] = tolower(comp.host[i]);
        }
        build_url(&comp, normalized);
    } else {
        strncpy(normalized, url, MAX_URL_LENGTH - 1);
    }
}

/* ============== Visited Set Operations ============== */

/* Check if URL has been visited */
int is_visited(CrawlerState *state, const char *url) {
    char normalized[MAX_URL_LENGTH];
    normalize_url(url, normalized);
    
    for (int i = 0; i < state->visited.count; i++) {
        if (state->visited.urls[i] && strcmp(state->visited.urls[i], normalized) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Mark URL as visited */
void mark_visited(CrawlerState *state, const char *url) {
    if (state->visited.count >= state->visited.capacity) {
        return;
    }
    char normalized[MAX_URL_LENGTH];
    normalize_url(url, normalized);
    state->visited.urls[state->visited.count] = strdup(normalized);
    state->visited.count++;
}

/* ============== Host Filtering ============== */

/* Check if host is in allowed list */
int is_allowed_host(CrawlerState *state, const char *host) {
    char lower_host[256];
    strncpy(lower_host, host, sizeof(lower_host) - 1);
    lower_host[sizeof(lower_host) - 1] = '\0';
    
    /* Lowercase */
    for (int i = 0; lower_host[i]; i++) {
        lower_host[i] = tolower(lower_host[i]);
    }
    
    /* Check against target host */
    if (strcmp(lower_host, state->target_host) == 0) {
        return 1;
    }
    
    /* Check if subdomain of target */
    size_t target_len = strlen(state->target_host);
    if (strlen(lower_host) > target_len) {
        if (strcmp(lower_host + strlen(lower_host) - target_len, state->target_host) == 0 &&
            lower_host[strlen(lower_host) - target_len - 1] == '.') {
            return 1;
        }
    }
    
    /* Check allowed hosts list */
    for (int i = 0; i < state->allowed_hosts_count; i++) {
        if (strstr(lower_host, state->allowed_hosts[i])) {
            return 1;
        }
    }
    
    return 0;
}

/* Check if host is blacklisted */
int is_blacklisted(CrawlerState *state, const char *host) {
    char lower_host[256];
    strncpy(lower_host, host, sizeof(lower_host) - 1);
    lower_host[sizeof(lower_host) - 1] = '\0';
    
    for (int i = 0; lower_host[i]; i++) {
        lower_host[i] = tolower(lower_host[i]);
    }
    
    /* Check default blacklist */
    for (int i = 0; DEFAULT_BLACKLIST[i] != NULL; i++) {
        if (strstr(lower_host, DEFAULT_BLACKLIST[i])) {
            return 1;
        }
    }
    
    /* Check custom blacklist */
    for (int i = 0; i < state->blacklist_count; i++) {
        if (strstr(lower_host, state->blacklist[i])) {
            return 1;
        }
    }
    
    return 0;
}

/* ============== Crawl Stack Operations ============== */

/* Push URL onto stack */
void push_url(CrawlerState *state, const char *url, int depth) {
    if (state->stack.top >= state->stack.capacity) {
        return;
    }
    state->stack.urls[state->stack.top] = strdup(url);
    state->stack.depths[state->stack.top] = depth;
    state->stack.top++;
}

/* Pop URL from stack */
char *pop_url(CrawlerState *state, int *depth) {
    if (state->stack.top <= 0) {
        return NULL;
    }
    state->stack.top--;
    *depth = state->stack.depths[state->stack.top];
    return state->stack.urls[state->stack.top];
}

/* ============== HTTP Fetching ============== */

/* Response buffer structure */
typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} ResponseBuffer;

/* Initialize response buffer */
ResponseBuffer *response_buffer_new() {
    ResponseBuffer *buf = malloc(sizeof(ResponseBuffer));
    buf->capacity = 8192;
    buf->data = malloc(buf->capacity);
    buf->size = 0;
    buf->data[0] = '\0';
    return buf;
}

/* Free response buffer */
void response_buffer_free(ResponseBuffer *buf) {
    if (buf) {
        free(buf->data);
        free(buf);
    }
}

/* Grow buffer if needed */
void response_buffer_grow(ResponseBuffer *buf, size_t needed) {
    while (buf->size + needed >= buf->capacity) {
        buf->capacity *= 2;
        buf->data = realloc(buf->data, buf->capacity);
    }
}

/* libcurl write callback */
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    ResponseBuffer *buf = (ResponseBuffer *)userp;
    
    response_buffer_grow(buf, realsize);
    memcpy(buf->data + buf->size, contents, realsize);
    buf->size += realsize;
    buf->data[buf->size] = '\0';
    
    return realsize;
}

/* Fetch a page using libcurl */
int fetch_page(CrawlerState *state, const char *url, char **content, long *content_len,
               int *status_code, char *content_type, char *http_date) {
    CURLcode res;
    ResponseBuffer *response;
    char *random_ua;
    int ua_index;
    
    *content = NULL;
    *content_len = 0;
    *status_code = 0;
    if (content_type) content_type[0] = '\0';
    if (http_date) http_date[0] = '\0';
    
    /* Initialize curl if needed */
    if (!state->curl) {
        state->curl = curl_easy_init();
        if (!state->curl) {
            fprintf(stderr, "Failed to initialize libcurl\n");
            return 0;
        }
    }
    
    /* Select random user agent */
    ua_index = rand() % state->user_agent_count;
    random_ua = state->user_agents[ua_index];
    
    /* Create response buffer */
    response = response_buffer_new();
    
    /* Set curl options */
    curl_easy_reset(state->curl);
    curl_easy_setopt(state->curl, CURLOPT_URL, url);
    curl_easy_setopt(state->curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(state->curl, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(state->curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(state->curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(state->curl, CURLOPT_USERAGENT, random_ua);
    curl_easy_setopt(state->curl, CURLOPT_COOKIEFILE, ""); /* Enable cookie engine */
    curl_easy_setopt(state->curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(state->curl, CURLOPT_WRITEDATA, response);
    curl_easy_setopt(state->curl, CURLOPT_SSL_VERIFYPEER, 0L); /* Skip SSL verification for demo */
    curl_easy_setopt(state->curl, CURLOPT_SSL_VERIFYHOST, 0L);
    
    /* Set browser-like headers */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
    headers = curl_slist_append(headers, "Accept-Language: en-US,en;q=0.5");
    headers = curl_slist_append(headers, "Accept-Encoding: gzip, deflate");
    headers = curl_slist_append(headers, "Connection: keep-alive");
    headers = curl_slist_append(headers, "Upgrade-Insecure-Requests: 1");
    curl_easy_setopt(state->curl, CURLOPT_HTTPHEADER, headers);
    
    /* Perform request */
    res = curl_easy_perform(state->curl);
    
    if (res != CURLE_OK) {
        fprintf(stderr, "curl error fetching %s: %s\n", url, curl_easy_strerror(res));
        response_buffer_free(response);
        curl_slist_free_all(headers);
        return 0;
    }
    
    /* Get response info */
    curl_easy_getinfo(state->curl, CURLINFO_RESPONSE_CODE, status_code);
    curl_easy_getinfo(state->curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, content_len);
    
    char *ct;
    curl_easy_getinfo(state->curl, CURLINFO_CONTENT_TYPE, &ct);
    if (ct && content_type) {
        strncpy(content_type, ct, 127);
    }
    
    char *date;
    curl_easy_getinfo(state->curl, CURLINFO_FILETIME_T, &date);
    if (date && http_date) {
        strncpy(http_date, date, 63);
    }
    
    /* Return content */
    *content = response->data;
    response->data = NULL; /* Transfer ownership */
    response_buffer_free(response);
    
    curl_slist_free_all(headers);
    
    /* Politeness delay */
    sleep_ms(REQUEST_DELAY_MS);
    
    return 1;
}

/* ============== HTML Parsing & Link Extraction ============== */

/* Callback for XPath evaluation */
typedef void (*XPathNodeCallback)(xmlChar *value, void *user_data);

/* Evaluate XPath expression and call callback for each result */
int evaluate_xpath(const char *html, const char *xpath_expr, XPathNodeCallback callback, void *user_data) {
    htmlDocPtr doc;
    xmlXPathContextPtr ctx;
    xmlXPathObjectPtr obj;
    
    /* Parse HTML */
    doc = htmlReadMemory(html, strlen(html), NULL, NULL, HTML_PARSE_RECOVER | HTML_PARSE_NOERROR | HTML_PARSE_NOWARNING);
    if (!doc) {
        return 0;
    }
    
    /* Create XPath context */
    ctx = xmlXPathNewContext(doc);
    if (!ctx) {
        xmlFreeDoc(doc);
        return 0;
    }
    
    /* Evaluate XPath */
    obj = xmlXPathEvalExpression(BAD_CAST xpath_expr, ctx);
    if (!obj || !obj->nodesetval) {
        xmlXPathFreeContext(ctx);
        xmlFreeDoc(doc);
        return 0;
    }
    
    /* Process results */
    xmlNodeSetPtr nodes = obj->nodesetval;
    for (int i = 0; i < nodes->nodeNr; i++) {
        xmlChar *value = xmlNodeGetContent(nodes->nodeTab[i]);
        if (value) {
            callback(value, user_data);
            xmlFree(value);
        }
    }
    
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctx);
    xmlFreeDoc(doc);
    
    return 1;
}

/* Link extraction callback data */
typedef struct {
    CrawlerState *state;
    char *base_url;
    int depth;
    int count;
} LinkExtractData;

/* Absolute URL resolution */
void resolve_absolute_url(const char *base, const char *relative, char *result) {
    URLComponents base_comp, rel_comp;
    
    /* If relative URL is already absolute */
    if (strstr(relative, "://")) {
        strncpy(result, relative, MAX_URL_LENGTH - 1);
        return;
    }
    
    parse_url(base, &base_comp);
    
    /* Handle different relative URL types */
    if (relative[0] == '/') {
        /* Absolute path */
        if (strlen(rel_comp.query) > 0) {
            sprintf(result, "%s://%s:%d%s?%s", 
                    base_comp.scheme, base_comp.host, base_comp.port, relative, rel_comp.query);
        } else {
            sprintf(result, "%s://%s:%d%s", 
                    base_comp.scheme, base_comp.host, base_comp.port, relative);
        }
    } else if (strncmp(relative, "#", 1) == 0) {
        /* Fragment only - skip */
        result[0] = '\0';
        return;
    } else if (strncmp(relative, "javascript:", 11) == 0 || 
               strncmp(relative, "mailto:", 7) == 0 ||
               strncmp(relative, "tel:", 4) == 0) {
        /* Non-HTTP schemes - skip */
        result[0] = '\0';
        return;
    } else {
        /* Relative path */
        char *last_slash = strrchr(base_comp.path, '/');
        if (last_slash) {
            char new_path[1024];
            int len = last_slash - base_comp.path + 1;
            strncpy(new_path, base_comp.path, len);
            new_path[len] = '\0';
            strcat(new_path, relative);
            
            if (strlen(rel_comp.query) > 0) {
                sprintf(result, "%s://%s:%d%s?%s", 
                        base_comp.scheme, base_comp.host, base_comp.port, new_path, rel_comp.query);
            } else {
                sprintf(result, "%s://%s:%d%s", 
                        base_comp.scheme, base_comp.host, base_comp.port, new_path);
            }
        } else {
            sprintf(result, "%s://%s:%d/%s", 
                    base_comp.scheme, base_comp.host, base_comp.port, relative);
        }
    }
}

/* Callback for processing extracted links */
void process_link(xmlChar *href, void *user_data) {
    LinkExtractData *data = (LinkExtractData *)user_data;
    char absolute_url[MAX_URL_LENGTH];
    URLComponents comp;
    
    /* Skip empty or invalid links */
    if (!href || strlen((char*)href) == 0) return;
    
    /* Resolve to absolute URL */
    resolve_absolute_url(data->base_url, (char*)href, absolute_url);
    if (strlen(absolute_url) == 0) return;
    
    /* Parse to get host */
    if (!parse_url(absolute_url, &comp)) return;
    
    /* Filter: skip blacklisted hosts */
    if (is_blacklisted(data->state, comp.host)) return;
    
    /* Filter: skip non-allowed hosts */
    if (!is_allowed_host(data->state, comp.host)) return;
    
    /* Filter: skip if already visited */
    if (is_visited(data->state, absolute_url)) return;
    
    /* Filter: skip certain file types */
    char *ext = strrchr(absolute_url, '.');
    if (ext) {
        if (strcasecmp(ext, ".pdf") == 0 || strcasecmp(ext, ".zip") == 0 ||
            strcasecmp(ext, ".exe") == 0 || strcasecmp(ext, ".doc") == 0 ||
            strcasecmp(ext, ".xls") == 0 || strcasecmp(ext, ".ppt") == 0) {
            return;
        }
    }
    
    /* Add to stack */
    push_url(data->state, absolute_url, data->depth + 1);
    data->count++;
}

/* Extract links from HTML content */
int extract_links(CrawlerState *state, const char *html, const char *base_url, int depth) {
    LinkExtractData data;
    data.state = state;
    data.base_url = (char*)base_url;
    data.depth = depth;
    data.count = 0;
    
    /* Extract <a href> links */
    evaluate_xpath(html, "//a/@href", process_link, &data);
    
    return data.count;
}

/* Asset extraction callback data */
typedef struct {
    CrawlerState *state;
    char *base_url;
    Asset assets[MAX_ASSETS_PER_PAGE];
    int count;
} AssetExtractData;

/* Callback for processing extracted assets */
void process_asset(xmlChar *src, void *user_data) {
    AssetExtractData *data = (AssetExtractData *)user_data;
    char absolute_url[MAX_URL_LENGTH];
    
    if (!src || strlen((char*)src) == 0) return;
    
    /* Resolve to absolute URL */
    resolve_absolute_url(data->base_url, (char*)src, absolute_url);
    if (strlen(absolute_url) == 0) return;
    
    if (data->count >= MAX_ASSETS_PER_PAGE) return;
    
    /* Determine asset type from extension */
    char *ext = strrchr(absolute_url, '.');
    const char *type = "unknown";
    if (ext) {
        if (strcasecmp(ext, ".jpg") == 0 || strcasecmp(ext, ".jpeg") == 0 ||
            strcasecmp(ext, ".png") == 0 || strcasecmp(ext, ".gif") == 0 ||
            strcasecmp(ext, ".svg") == 0 || strcasecmp(ext, ".webp") == 0 ||
            strcasecmp(ext, ".ico") == 0) {
            type = "image";
        } else if (strcasecmp(ext, ".js") == 0) {
            type = "script";
        } else if (strcasecmp(ext, ".css") == 0) {
            type = "stylesheet";
        } else if (strcasecmp(ext, ".woff") == 0 || strcasecmp(ext, ".woff2") == 0 ||
                   strcasecmp(ext, ".ttf") == 0 || strcasecmp(ext, ".eot") == 0) {
            type = "font";
        } else if (strcasecmp(ext, ".mp4") == 0 || strcasecmp(ext, ".webm") == 0 ||
                   strcasecmp(ext, ".ogg") == 0 || strcasecmp(ext, ".mp3") == 0) {
            type = "media";
        }
    }
    
    strncpy(data->assets[data->count].url, absolute_url, MAX_URL_LENGTH - 1);
    strncpy(data->assets[data->count].type, type, sizeof(data->assets[data->count].type) - 1);
    data->count++;
}

/* Extract assets from HTML content */
int extract_assets(CrawlerState *state, const char *html, const char *base_url) {
    AssetExtractData data;
    data.state = state;
    data.base_url = (char*)base_url;
    data.count = 0;
    
    /* Extract images */
    evaluate_xpath(html, "//img/@src", process_asset, &data);
    
    /* Extract scripts */
    evaluate_xpath(html, "//script/@src", process_asset, &data);
    
    /* Extract stylesheets */
    evaluate_xpath(html, "//link[@rel='stylesheet']/@href", process_asset, &data);
    evaluate_xpath(html, "//link[@rel='styleSheet']/@href", process_asset, &data);
    
    /* Insert assets to database */
    if (data.count > 0 && state->db_conn) {
        /* Note: We'd need the page_id here, but for simplicity we skip FK in this demo */
        // insert_assets_to_db(state, page_id, data.assets, data.count);
        printf("  Found %d assets\n", data.count);
    }
    
    return data.count;
}

/* ============== URL Parameter Extraction ============== */

/* Extract parameters from URL query string */
int extract_url_params(const char *url, URLParam *params, int *count) {
    URLComponents comp;
    char *query, *token, *saveptr;
    char query_copy[1024];
    
    *count = 0;
    
    if (!parse_url(url, &comp)) return 0;
    if (strlen(comp.query) == 0) return 0;
    
    strncpy(query_copy, comp.query, sizeof(query_copy) - 1);
    query_copy[sizeof(query_copy) - 1] = '\0';
    
    query = query_copy;
    token = strtok_r(query, "&", &saveptr);
    
    while (token && *count < MAX_PARAMS_PER_URL) {
        char *eq = strchr(token, '=');
        if (eq) {
            *eq = '\0';
            strncpy(params[*count].name, token, sizeof(params[*count].name) - 1);
            strncpy(params[*count].value, eq + 1, sizeof(params[*count].value) - 1);
        } else {
            strncpy(params[*count].name, token, sizeof(params[*count].name) - 1);
            params[*count].value[0] = '\0';
        }
        (*count)++;
        token = strtok_r(NULL, "&", &saveptr);
    }
    
    return *count;
}

/* ============== Database Operations ============== */

/* Insert crawled page to database */
int insert_page_to_db(CrawlerState *state, CrawledPage *page) {
    char escaped_url[MAX_URL_LENGTH * 2];
    char escaped_host[512];
    char escaped_path[2048];
    char escaped_query[2048];
    char escaped_content_type[256];
    char escaped_http_date[128];
    char sql[4096];
    int page_id = -1;
    
    if (!state->db_conn) return -1;
    
    /* Escape strings */
    sql_escape(state->db_conn, page->full_url, escaped_url, sizeof(escaped_url));
    sql_escape(state->db_conn, page->host, escaped_host, sizeof(escaped_host));
    sql_escape(state->db_conn, page->path, escaped_path, sizeof(escaped_path));
    sql_escape(state->db_conn, page->query, escaped_query, sizeof(escaped_query));
    sql_escape(state->db_conn, page->content_type, escaped_content_type, sizeof(escaped_content_type));
    sql_escape(state->db_conn, page->http_date, escaped_http_date, sizeof(escaped_http_date));
    
    /* Insert page record */
    sprintf(sql, 
        "INSERT INTO pages (full_url, host, path, query, status_code, content_length, "
        "content_type, http_date, depth, crawled_at) "
        "VALUES ('%s', '%s', '%s', '%s', %d, %ld, '%s', '%s', %d, FROM_UNIXTIME(%ld))",
        escaped_url, escaped_host, escaped_path, escaped_query,
        page->status_code, page->content_length, escaped_content_type, 
        escaped_http_date, page->depth, (long)page->crawled_at);
    
    if (mysql_query(state->db_conn, sql)) {
        fprintf(stderr, "DB insert error: %s\n", mysql_error(state->db_conn));
        return -1;
    }
    
    /* Get inserted ID */
    page_id = mysql_insert_id(state->db_conn);
    
    return page_id;
}

/* Insert URL parameters to database */
int insert_params_to_db(CrawlerState *state, int page_id, URLParam *params, int count) {
    char escaped_name[512];
    char escaped_value[1024];
    char sql[2048];
    
    if (!state->db_conn || count <= 0) return 0;
    
    for (int i = 0; i < count; i++) {
        sql_escape(state->db_conn, params[i].name, escaped_name, sizeof(escaped_name));
        sql_escape(state->db_conn, params[i].value, escaped_value, sizeof(escaped_value));
        
        sprintf(sql,
            "INSERT INTO url_params (page_id, param_name, param_value) "
            "VALUES (%d, '%s', '%s')",
            page_id, escaped_name, escaped_value);
        
        if (mysql_query(state->db_conn, sql)) {
            fprintf(stderr, "DB param insert error: %s\n", mysql_error(state->db_conn));
        }
    }
    
    return count;
}

/* Insert assets to database */
int insert_assets_to_db(CrawlerState *state, int page_id, Asset *assets, int count) {
    char escaped_url[MAX_URL_LENGTH * 2];
    char escaped_type[64];
    char sql[4096];
    
    if (!state->db_conn || count <= 0) return 0;
    
    for (int i = 0; i < count; i++) {
        sql_escape(state->db_conn, assets[i].url, escaped_url, sizeof(escaped_url));
        sql_escape(state->db_conn, assets[i].type, escaped_type, sizeof(escaped_type));
        
        sprintf(sql,
            "INSERT INTO assets (page_id, asset_url, asset_type) "
            "VALUES (%d, '%s', '%s')",
            page_id, escaped_url, escaped_type);
        
        if (mysql_query(state->db_conn, sql)) {
            fprintf(stderr, "DB asset insert error: %s\n", mysql_error(state->db_conn));
        }
    }
    
    return count;
}

/* ============== Crawler Initialization ============== */

/* Initialize crawler state */
int init_crawler(CrawlerState *state) {
    memset(state, 0, sizeof(CrawlerState));
    
    /* Initialize stack with dynamic allocation */
    state->stack.capacity = MAX_VISITED_URLS;
    state->stack.urls = calloc(state->stack.capacity, sizeof(char*));
    state->stack.depths = calloc(state->stack.capacity, sizeof(int));
    state->stack.top = 0;
    
    /* Initialize visited set with dynamic allocation */
    state->visited.capacity = MAX_VISITED_URLS;
    state->visited.urls = calloc(state->visited.capacity, sizeof(char*));
    state->visited.count = 0;
    
    /* Initialize random seed */
    srand(time(NULL));
    
    /* Copy default user agents */
    state->user_agent_count = 0;
    for (int i = 0; USER_AGENTS[i] != NULL && state->user_agent_count < MAX_USER_AGENTS; i++) {
        strncpy(state->user_agents[state->user_agent_count], USER_AGENTS[i], 511);
        state->user_agent_count++;
    }
    
    /* Copy default blacklist */
    state->blacklist_count = 0;
    state->blacklist = NULL;
    
    /* Initialize allowed hosts */
    state->allowed_hosts_count = 0;
    state->allowed_hosts = NULL;
    
    /* Set defaults */
    state->max_depth = MAX_DEPTH;
    state->max_pages = MAX_VISITED_URLS;
    state->pages_crawled = 0;
    
    /* Initialize libcurl */
    if (curl_global_init(CURL_GLOBAL_ALL) != 0) {
        fprintf(stderr, "Failed to initialize libcurl\n");
        return 0;
    }
    state->curl = NULL;
    
    /* Initialize MySQL connection */
    state->db_conn = NULL;
    
    return 1;
}

/* Connect to MySQL database */
int connect_database(CrawlerState *state, const char *host, const char *user, 
                     const char *pass, const char *dbname, int port) {
    state->db_conn = mysql_init(NULL);
    if (!state->db_conn) {
        fprintf(stderr, "MySQL init failed\n");
        return 0;
    }
    
    if (!mysql_real_connect(state->db_conn, host, user, pass, dbname, port, NULL, 0)) {
        fprintf(stderr, "MySQL connect failed: %s\n", mysql_error(state->db_conn));
        mysql_close(state->db_conn);
        state->db_conn = NULL;
        return 0;
    }
    
    printf("Connected to MySQL database: %s@%s:%d/%s\n", user, host, port, dbname);
    return 1;
}

/* Cleanup crawler state */
void cleanup_crawler(CrawlerState *state) {
    /* Free curl */
    if (state->curl) {
        curl_easy_cleanup(state->curl);
        state->curl = NULL;
    }
    curl_global_cleanup();
    
    /* Close database */
    if (state->db_conn) {
        mysql_close(state->db_conn);
        state->db_conn = NULL;
    }
    
    /* Free stack URLs and arrays */
    if (state->stack.urls) {
        for (int i = 0; i < state->stack.top; i++) {
            free(state->stack.urls[i]);
        }
        free(state->stack.urls);
        free(state->stack.depths);
    }
    
    /* Free visited URLs */
    if (state->visited.urls) {
        for (int i = 0; i < state->visited.count; i++) {
            free(state->visited.urls[i]);
        }
        free(state->visited.urls);
    }
    
    /* Free allowed hosts */
    if (state->allowed_hosts) {
        for (int i = 0; i < state->allowed_hosts_count; i++) {
            free(state->allowed_hosts[i]);
        }
        free(state->allowed_hosts);
    }
    
    /* Free blacklist */
    if (state->blacklist) {
        for (int i = 0; i < state->blacklist_count; i++) {
            free(state->blacklist[i]);
        }
        free(state->blacklist);
    }
}

/* ============== Main Crawl Loop ============== */

/* Crawl function - depth-first traversal */
void crawl(CrawlerState *state) {
    char *url;
    int depth;
    
    printf("\n=== Starting Depth-First Crawl ===\n");
    printf("Target host: %s\n", state->target_host);
    printf("Max depth: %d\n", state->max_depth);
    printf("Initial frontier size: %d\n", state->stack.top);
    printf("===============================\n\n");
    
    while ((url = pop_url(state, &depth)) != NULL) {
        /* Check depth limit */
        if (depth > state->max_depth) {
            printf("[SKIP] Depth exceeded: %s (depth=%d)\n", url, depth);
            continue;
        }
        
        /* Check if already visited */
        if (is_visited(state, url)) {
            continue;
        }
        
        /* Check page limit */
        if (state->pages_crawled >= state->max_pages) {
            printf("[STOP] Max pages reached: %d\n", state->max_pages);
            break;
        }
        
        /* Mark as visited */
        mark_visited(state, url);
        state->pages_crawled++;
        
        printf("[%d/%d] Crawling (depth=%d): %s\n", 
               state->pages_crawled, state->max_pages, depth, url);
        
        /* Fetch page */
        char *content = NULL;
        long content_len = 0;
        int status_code = 0;
        char content_type[128] = {0};
        char http_date[64] = {0};
        
        if (!fetch_page(state, url, &content, &content_len, &status_code, 
                       content_type, http_date)) {
            printf("  [ERROR] Failed to fetch page\n");
            if (content) free(content);
            continue;
        }
        
        printf("  Status: %d, Size: %ld bytes, Type: %s\n", 
               status_code, content_len, content_type[0] ? content_type : "unknown");
        
        /* Record page if status is of interest */
        if (status_code == 200 || status_code == 403 || status_code == 500) {
            CrawledPage page;
            URLComponents comp;
            
            memset(&page, 0, sizeof(page));
            strncpy(page.full_url, url, sizeof(page.full_url) - 1);
            page.status_code = status_code;
            page.content_length = content_len;
            strncpy(page.content_type, content_type, sizeof(page.content_type) - 1);
            strncpy(page.http_date, http_date, sizeof(page.http_date) - 1);
            page.depth = depth;
            page.crawled_at = time(NULL);
            
            /* Parse URL for components */
            if (parse_url(url, &comp)) {
                strncpy(page.host, comp.host, sizeof(page.host) - 1);
                strncpy(page.path, comp.path, sizeof(page.path) - 1);
                strncpy(page.query, comp.query, sizeof(page.query) - 1);
            }
            
            /* Insert to database */
            if (state->db_conn) {
                int page_id = insert_page_to_db(state, &page);
                
                /* Extract and store URL parameters */
                URLParam params[MAX_PARAMS_PER_URL];
                int param_count = 0;
                if (extract_url_params(url, params, &param_count) > 0) {
                    printf("  Parameters: %d found\n", param_count);
                    if (page_id > 0) {
                        insert_params_to_db(state, page_id, params, param_count);
                    }
                }
            }
            
            /* Extract links and assets if HTML */
            if (content && strstr(content_type, "text/html")) {
                int links_found = extract_links(state, content, url, depth);
                printf("  Links extracted: %d\n", links_found);
                
                int assets_found = extract_assets(state, content, url);
                printf("  Assets extracted: %d\n", assets_found);
            }
        }
        
        if (content) free(content);
    }
    
    printf("\n=== Crawl Complete ===\n");
    printf("Total pages crawled: %d\n", state->pages_crawled);
    printf("Total URLs visited: %d\n", state->visited.count);
}

/* ============== Seed Loading ============== */

/* Load seeds from file or command line */
int load_seeds(const char *input, char **seeds, int *count) {
    FILE *fp;
    char line[1024];
    char *temp_hosts[MAX_HOSTS];
    int temp_count = 0;
    
    *count = 0;
    
    /* Check if input is a file */
    fp = fopen(input, "r");
    if (fp) {
        printf("Loading seeds from file: %s\n", input);
        while (fgets(line, sizeof(line), fp) && temp_count < MAX_HOSTS) {
            char *trimmed = trim(line);
            if (strlen(trimmed) == 0 || trimmed[0] == '#') continue;
            
            /* Expand CIDR if present */
            if (strchr(trimmed, '/')) {
                int cidr_count = 0;
                expand_cidr(trimmed, temp_hosts + temp_count, &cidr_count);
                temp_count += cidr_count;
            } else {
                temp_hosts[temp_count++] = strdup(trimmed);
            }
        }
        fclose(fp);
    } else {
        /* Treat as comma-separated list or single seed */
        char *token, *saveptr;
        char input_copy[4096];
        
        strncpy(input_copy, input, sizeof(input_copy) - 1);
        token = strtok_r(input_copy, ",", &saveptr);
        
        while (token && temp_count < MAX_HOSTS) {
            char *trimmed = trim(token);
            if (strlen(trimmed) > 0) {
                /* Expand CIDR if present */
                if (strchr(trimmed, '/')) {
                    int cidr_count = 0;
                    expand_cidr(trimmed, temp_hosts + temp_count, &cidr_count);
                    temp_count += cidr_count;
                } else {
                    temp_hosts[temp_count++] = strdup(trimmed);
                }
            }
            token = strtok_r(NULL, ",", &saveptr);
        }
    }
    
    /* Convert hosts to URLs and add to seeds */
    for (int i = 0; i < temp_count && *count < MAX_HOSTS; i++) {
        char *host = temp_hosts[i];
        char url[MAX_URL_LENGTH];
        
        /* Check if already a URL */
        if (strstr(host, "://")) {
            seeds[*count] = strdup(host);
            (*count)++;
        } else {
            /* Construct URL */
            sprintf(url, "http://%s/", host);
            seeds[*count] = strdup(url);
            (*count)++;
        }
        
        free(host);
    }
    
    return *count;
}

/* Set target host from seed */
void set_target_host(CrawlerState *state, const char *seed_url) {
    URLComponents comp;
    
    if (parse_url(seed_url, &comp)) {
        strncpy(state->target_host, comp.host, sizeof(state->target_host) - 1);
        
        /* Lowercase */
        for (int i = 0; state->target_host[i]; i++) {
            state->target_host[i] = tolower(state->target_host[i]);
        }
        
        /* Remove www. prefix if present */
        if (strncmp(state->target_host, "www.", 4) == 0) {
            memmove(state->target_host, state->target_host + 4, 
                   strlen(state->target_host) - 3);
        }
        
        printf("Target host set to: %s\n", state->target_host);
    }
}

/* ============== Usage Information ============== */

void print_usage(const char *prog) {
    printf("C-Based Web Crawler with Depth-First Traversal\n\n");
    printf("Usage: %s [OPTIONS] <seed>\n\n", prog);
    printf("Options:\n");
    printf("  -s, --seed <seed>       Seed URL, domain, IP, or CIDR range\n");
    printf("  -f, --file <file>       Load seeds from file (one per line)\n");
    printf("  -d, --depth <depth>     Maximum crawl depth (default: %d)\n", MAX_DEPTH);
    printf("  -m, --max-pages <num>   Maximum pages to crawl (default: %d)\n", MAX_VISITED_URLS);
    printf("  -H, --host <host>       Target host to restrict crawling\n");
    printf("  -b, --blacklist <list>  Comma-separated blacklist domains\n");
    printf("  -D, --db-host <host>    MySQL database host (default: localhost)\n");
    printf("  -u, --db-user <user>    MySQL username\n");
    printf("  -p, --db-pass <pass>    MySQL password\n");
    printf("  -n, --db-name <name>    MySQL database name\n");
    printf("  -P, --db-port <port>    MySQL port (default: 3306)\n");
    printf("  -v, --verbose           Verbose output\n");
    printf("  -h, --help              Show this help message\n\n");
    printf("Examples:\n");
    printf("  %s -s example.com\n", prog);
    printf("  %s -f seeds.txt -d 5 -m 1000\n", prog);
    printf("  %s -s 192.168.1.0/24 --db-host localhost --db-user root --db-name crawler\n", prog);
    printf("\nDatabase Schema:\n");
    printf("  CREATE TABLE pages (\n");
    printf("    id INT AUTO_INCREMENT PRIMARY KEY,\n");
    printf("    full_url VARCHAR(2048),\n");
    printf("    host VARCHAR(256),\n");
    printf("    path VARCHAR(1024),\n");
    printf("    query VARCHAR(1024),\n");
    printf("    status_code INT,\n");
    printf("    content_length BIGINT,\n");
    printf("    content_type VARCHAR(128),\n");
    printf("    http_date VARCHAR(64),\n");
    printf("    depth INT,\n");
    printf("    crawled_at DATETIME\n");
    printf("  );\n\n");
    printf("  CREATE TABLE url_params (\n");
    printf("    id INT AUTO_INCREMENT PRIMARY KEY,\n");
    printf("    page_id INT,\n");
    printf("    param_name VARCHAR(256),\n");
    printf("    param_value VARCHAR(512),\n");
    printf("    FOREIGN KEY (page_id) REFERENCES pages(id)\n");
    printf("  );\n\n");
    printf("  CREATE TABLE assets (\n");
    printf("    id INT AUTO_INCREMENT PRIMARY KEY,\n");
    printf("    page_id INT,\n");
    printf("    asset_url VARCHAR(2048),\n");
    printf("    asset_type VARCHAR(32),\n");
    printf("    FOREIGN KEY (page_id) REFERENCES pages(id)\n");
    printf("  );\n");
}

/* ============== Main Function ============== */

int main(int argc, char *argv[]) {
    CrawlerState state;
    char *seeds[MAX_HOSTS];
    int seed_count = 0;
    
    /* Default values */
    char *db_host = "localhost";
    char *db_user = NULL;
    char *db_pass = NULL;
    char *db_name = NULL;
    int db_port = 3306;
    char *seed_input = NULL;
    char *seed_file = NULL;
    char *target_host = NULL;
    char *blacklist_input = NULL;
    
    /* Parse command line arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--seed") == 0) {
            if (++i < argc) seed_input = argv[i];
        } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--file") == 0) {
            if (++i < argc) seed_file = argv[i];
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--depth") == 0) {
            if (++i < argc) state.max_depth = atoi(argv[i]);
        } else if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--max-pages") == 0) {
            if (++i < argc) state.max_pages = atoi(argv[i]);
        } else if (strcmp(argv[i], "-H") == 0 || strcmp(argv[i], "--host") == 0) {
            if (++i < argc) target_host = argv[i];
        } else if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--blacklist") == 0) {
            if (++i < argc) blacklist_input = argv[i];
        } else if (strcmp(argv[i], "-D") == 0 || strcmp(argv[i], "--db-host") == 0) {
            if (++i < argc) db_host = argv[i];
        } else if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--db-user") == 0) {
            if (++i < argc) db_user = argv[i];
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--db-pass") == 0) {
            if (++i < argc) db_pass = argv[i];
        } else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--db-name") == 0) {
            if (++i < argc) db_name = argv[i];
        } else if (strcmp(argv[i], "-P") == 0 || strcmp(argv[i], "--db-port") == 0) {
            if (++i < argc) db_port = atoi(argv[i]);
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }
    
    /* Require at least one seed */
    if (!seed_input && !seed_file) {
        fprintf(stderr, "Error: No seed provided. Use -s or -f option.\n\n");
        print_usage(argv[0]);
        return 1;
    }
    
    /* Initialize crawler */
    if (!init_crawler(&state)) {
        fprintf(stderr, "Failed to initialize crawler\n");
        return 1;
    }
    
    /* Load seeds */
    if (seed_file) {
        load_seeds(seed_file, seeds, &seed_count);
    }
    if (seed_input) {
        int additional = 0;
        load_seeds(seed_input, seeds + seed_count, &additional);
        seed_count += additional;
    }
    
    if (seed_count == 0) {
        fprintf(stderr, "No valid seeds loaded\n");
        cleanup_crawler(&state);
        return 1;
    }
    
    printf("Loaded %d seed(s)\n", seed_count);
    
    /* Set target host from first seed */
    if (target_host) {
        strncpy(state.target_host, target_host, sizeof(state.target_host) - 1);
        printf("Target host set to: %s\n", state.target_host);
    } else {
        set_target_host(&state, seeds[0]);
    }
    
    /* Parse blacklist */
    if (blacklist_input) {
        char *token, *saveptr;
        char blacklist_copy[1024];
        
        strncpy(blacklist_copy, blacklist_input, sizeof(blacklist_copy) - 1);
        token = strtok_r(blacklist_copy, ",", &saveptr);
        
        while (token) {
            char *trimmed = trim(token);
            if (strlen(trimmed) > 0) {
                state.blacklist = realloc(state.blacklist, 
                                         (state.blacklist_count + 1) * sizeof(char*));
                state.blacklist[state.blacklist_count++] = strdup(trimmed);
            }
            token = strtok_r(NULL, ",", &saveptr);
        }
    }
    
    /* Connect to database if credentials provided */
    if (db_user && db_name) {
        if (!connect_database(&state, db_host, db_user, db_pass, db_name, db_port)) {
            fprintf(stderr, "Warning: Database connection failed. Continuing without DB.\n");
        }
    } else {
        printf("No database credentials provided. Running without database storage.\n");
    }
    
    /* Push all seeds to stack */
    for (int i = 0; i < seed_count; i++) {
        push_url(&state, seeds[i], 0);
        free(seeds[i]);
    }
    
    /* Start crawling */
    crawl(&state);
    
    /* Cleanup */
    cleanup_crawler(&state);
    
    return 0;
}
