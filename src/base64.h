
#ifndef H_HTTP_BASE64_H
#define H_HTTP_BASE64_H


/* Generate a mask of LENGTH one-bits, right justified in a word.  */
#define MASK(Length) ((unsigned) ~(~0 << (Length)))

/* Indicate if CHARACTER holds into 7 bits.  */
#define IS_ASCII(Character) \
  (!((Character) & ~MASK (7)))

/* Maximum number of characters per MIME line.  */
#define MIME_LINE_LENGTH 76

/* Tables declared in base64.c and also used in utf7.c.  */
extern char httpproxy_base64_value_to_char[64];
extern int httpproxy_base64_char_to_value[128];
extern char base64_charset[64];

/* Macros.  */
#define IS_BASE64(Character) \
  (IS_ASCII (Character) && httpproxy_base64_char_to_value[(int)(Character)] >= 0)


#ifdef __cplusplus
extern "C" {
#endif

int http_proxy_base64_decode(int flag_quote,char *src_buf,int srclen, char *dest);


#ifdef __cplusplus
}
#endif


#endif // H_MIME_BASE64_H
