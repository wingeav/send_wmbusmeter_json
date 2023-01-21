/* needs libssl-dev
   compile: gcc send_heater_water.c -o send_heater_water -lcrypto -lssl
   example usage: ./send_heater_water "{\"media\":\"water\",\"meter\":\"qwater\",\"name\":\"cold_water\",\"id\":\"12345678\",\"meter_datetime\":\"2023-01-20 20:06\",\"total_m3\":11.409,\"status\":\"OK\",\"due_date_m3\":10.789,\"due_date\":\"2022-12-31\",\"due_17_date_m3\":10.789,\"due_17_date\":\"2022-12-31\",\"volume_flow_m3h\":0,\"error_date\":\"1970-01-01\",\"timestamp\":\"2023-01-20T19:06:48Z\",\"device\":\"rtlwmbus[00000001]\",\"rssi_dbm\":139}"
*/
#define HOST_NAME "mydomain.com"
#define HOST_PORT "443"
#define URL "/json_heater_water.php"
#define PASSWORD "Very secret! Don't tell anyone!!"

#include "stdio.h"
#include "string.h"
#include "openssl/ssl.h"
#include "openssl/bio.h"
#include "openssl/err.h"

int main(int argc, char *argv[])
{
  //print "help"
  if ((argc != 2) || (strcmp(argv[1], "-v") == 0) || (strcmp(argv[1], "-h") == 0) || (strcmp(argv[1], "--help") == 0)) {
    printf ("Tool to POST json data from wmbusmeters to webserver\n");
    printf ("Usage: ./send_heater_water {JSON} \n");
    printf ("example usage: ./send_heater_water \\\"{\\\"media\\\":\\\"water\\\",\\\"meter\\\":\\\"qwater\\\",\\\"name\\\":\\\"cold_water\\\",\\\"id\\\":\\\"12345678\\\",\\\"meter_datetime\\\":\\\"2023-01-20 20:06\\\",\\\"total_m3\\\":11.409,\\\"status\\\":\\\"OK\\\",\\\"due_date_m3\\\":10.789,\\\"due_date\\\":\\\"2022-12-31\\\",\\\"due_17_date_m3\\\":10.789,\\\"due_17_date\\\":\\\"2022-12-31\\\",\\\"volume_flow_m3h\\\":0,\\\"error_date\\\":\\\"1970-01-01\\\",\\\"timestamp\\\":\\\"2023-01-20T19:06:48Z\\\",\\\"device\\\":\\\"rtlwmbus[00000001]\\\",\\\"rssi_dbm\\\":139}\"\n\n\n");
    return 0;
  }
    
  SSL * ssl = NULL;
  SSL_CTX * ctx = NULL;
  BIO * bio = NULL;
  char jsondata[1024]="";

  // Delete the last "}" of the json parameter and add the password at the end
  strncpy(jsondata,argv[1],strlen(argv[1])-2);
  strcat(jsondata,",\"password\":\"" PASSWORD "\"}");
  
  //Init SSL library
  SSL_library_init();
  ERR_load_BIO_strings();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();

  //Set up SSL context
  const SSL_METHOD *method = TLS_client_method();	
  if (! method) {
      fprintf(stderr, " TLS_client_method \n");
      return 1;
  }

  // Set up TLS method
  ctx = SSL_CTX_new(method);
  if (! ctx) {  
      fprintf(stderr, " SSL context is NULL\n");
      ERR_print_errors_fp(stderr);
      return 1;
  }

  //disable old TLS protocols
  const long flags = SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1; 
  SSL_CTX_set_options(ctx, flags);

  // use CA verification Default directory
  if(SSL_CTX_set_default_verify_dir(ctx) < 1) {
      fprintf(stderr, "VERIFYDIR\n");
      ERR_print_errors_fp(stderr);
      BIO_free_all(bio);
      SSL_CTX_free(ctx);
      return 0;
  }

  //Setup connection
  bio = BIO_new_ssl_connect(ctx);

  //Set SSL_MODE_AUTO_RETRY flag
  BIO_get_ssl(bio, &ssl);
  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

  //Create and setup connection
  BIO_set_conn_hostname(bio, HOST_NAME ":" HOST_PORT);

  //Set Hostname for SNI
  if(SSL_set_tlsext_host_name(ssl, HOST_NAME) < 1) {
      fprintf(stderr, "TLSEXT\n");
      ERR_print_errors_fp(stderr);
      BIO_free_all(bio);
      SSL_CTX_free(ctx);
      return 0;
  }

  // connect
  if(BIO_do_connect(bio) < 1) {
      fprintf(stderr, "Error attempting to connect\n");
      ERR_print_errors_fp(stderr);
      BIO_free_all(bio);
      SSL_CTX_free(ctx);
      return 0;
  }

  if(BIO_do_handshake(bio) < 1) {
      fprintf(stderr, "HANDSHAKE\n");
      ERR_print_errors_fp(stderr);
      BIO_free_all(bio);
      SSL_CTX_free(ctx);
      return 0;
  }

  // Check for certificate errors
  if(SSL_get_verify_result(ssl) != X509_V_OK)
  {
      fprintf(stderr, "Certificate verification error: %ld\n", SSL_get_verify_result(ssl));
      fprintf(stderr, "Error: %s\n", ERR_reason_error_string(ERR_get_error()));
      ERR_print_errors_fp(stderr);
      BIO_free_all(bio);
      SSL_CTX_free(ctx);
      return 0;
  }

  //prepare send buffer
  char buffer [1500]="";
  sprintf(buffer,"POST " URL " HTTP/1.1\r\n"
                "Host: " HOST_NAME "\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: 1024\r\n"
                "\r\n"
                "%s\r\n"
                "\r\n"
                "\r\n",jsondata);
  // Send request
  BIO_puts(bio, buffer);

  //Close  connection
  BIO_free_all(bio);
  SSL_CTX_free(ctx);
  return 0;
}