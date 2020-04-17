#include <mruby.h>
#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/string.h>
#include <mruby/value.h>
#define HTTPSERVER_IMPL
#include "../httpserver.h/httpserver.h"

static void null_free(mrb_state* mrb, void* p) { }

typedef struct {
  mrb_state* mrb;
  mrb_value server;
} mrb_evt_http_server;

typedef struct {
  mrb_state* mrb;
  mrb_value blk;
  mrb_value request;
} mrb_req_cb_t;

static struct RClass* reqclass = NULL;

struct mrb_data_type const mrb_evt_http_server_type = { "AsyncHttpServer::Server", null_free };
struct mrb_data_type const mrb_evt_http_request_type = { "AsyncHttpServer::Request", null_free };
struct mrb_data_type const mrb_evt_http_response_type = { "AsyncHttpServer::Response", null_free };

// *** request ***

static mrb_value request_respond(mrb_state* mrb, mrb_value self) {
  struct http_request_s* request = DATA_PTR(self);
  mrb_value res;
  mrb_get_args(mrb, "o", &res);
  http_respond(request, DATA_PTR(res));
  return self;
}

static mrb_value request_method(mrb_state* mrb, mrb_value self) {
  struct http_request_s* request = DATA_PTR(self);
  struct http_string_s method = http_request_method(request);
  return mrb_str_new_static(mrb, method.buf, method.len);
}

static mrb_value request_target(mrb_state* mrb, mrb_value self) {
  struct http_request_s* request = DATA_PTR(self);
  struct http_string_s target = http_request_target(request);
  return mrb_str_new_static(mrb, target.buf, target.len);
}

static mrb_value request_body(mrb_state* mrb, mrb_value self) {
  struct http_request_s* request = DATA_PTR(self);
  struct http_string_s body = http_request_body(request);
  return mrb_str_new_static(mrb, body.buf, body.len);
}

static mrb_value request_header(mrb_state* mrb, mrb_value self) {
  struct http_request_s* request = DATA_PTR(self);
  char* key;
  mrb_get_args(mrb, "z", &key);
  struct http_string_s value = http_request_header(request, key);
  return mrb_str_new_static(mrb, value.buf, value.len);
}

static mrb_value request_streamed(mrb_state* mrb, mrb_value self) {
  struct http_request_s* request = DATA_PTR(self);
  int streamed = http_request_has_flag(request, HTTP_FLG_STREAMED);
  return streamed ? mrb_true_value() : mrb_false_value();
}

static mrb_value request_each_header(mrb_state* mrb, mrb_value self) {
  struct http_request_s* request = DATA_PTR(self);
  int i = 0;
  mrb_value blk;
  struct http_string_s k, v;
  mrb_get_args(mrb, "&!", &blk);
  while(http_request_iterate_headers(request, &k, &v, &i)) {
    mrb_value args[2];
    args[0] = mrb_str_new_static(mrb, k.buf, k.len);
    args[1] = mrb_str_new_static(mrb, v.buf, v.len);
    mrb_yield_argv(mrb, blk, 2, args);
  }
  return self;
}

static void request_callback(struct http_request_s* request) {
  mrb_req_cb_t* cb = http_request_userdata(request);
  mrb_yield(cb->mrb, cb->blk, cb->request);
}

static mrb_value request_respond_chunk(mrb_state* mrb, mrb_value self) {
  struct http_request_s* request = DATA_PTR(self);
  mrb_value res, blk;
  mrb_get_args(mrb, "o&!", &res, &blk);
  mrb_req_cb_t* cb = mrb_malloc(mrb, sizeof(mrb_req_cb_t));
  cb->mrb = mrb;
  cb->request = self;
  cb->blk = blk;
  http_request_set_userdata(request, cb);
  http_respond_chunk(request, DATA_PTR(res), request_callback);
  return self;
}

static mrb_value request_chunk_end(mrb_state* mrb, mrb_value self) {
  struct http_request_s* request = DATA_PTR(self);
  struct http_response_s* res = http_response_init();
  http_respond_chunk_end(request, res);
  return self;
}

static mrb_value request_read_chunk(mrb_state* mrb, mrb_value self) {
  struct http_request_s* request = DATA_PTR(self);
  mrb_value blk;
  mrb_get_args(mrb, "&!", &blk);
  mrb_req_cb_t* cb = mrb_malloc(mrb, sizeof(mrb_req_cb_t));
  cb->mrb = mrb;
  cb->request = self;
  cb->blk = blk;
  http_request_set_userdata(request, cb);
  http_request_read_chunk(request, request_callback);
  return self;
}

// *** response ***

static mrb_value response_init(mrb_state* mrb, mrb_value self) {
  struct http_response_s* response = http_response_init();
  DATA_TYPE(self) = &mrb_evt_http_response_type;
  DATA_PTR(self) = response;
  return self;
}

static mrb_value response_set_status(mrb_state* mrb, mrb_value self) {
  struct http_response_s* response = DATA_PTR(self);
  mrb_int status;
  mrb_get_args(mrb, "i", &status);
  http_response_status(response, status);
  return self;
}

static mrb_value response_set_body(mrb_state* mrb, mrb_value self) {
  struct http_response_s* response = DATA_PTR(self);
  mrb_value str;
  mrb_get_args(mrb, "S", &str);
  http_response_body(response, RSTRING_CSTR(mrb, str), RSTRING_LEN(str));
  return str;
}

static mrb_value response_set_header(mrb_state* mrb, mrb_value self) {
  struct http_response_s* response = DATA_PTR(self);
  char* key, *value;
  mrb_get_args(mrb, "zz", &key, &value);
  http_response_header(response, key, value);
  return self;
}

// *** server ***

static void handle_request(struct http_request_s* request) {
  mrb_evt_http_server* mrbctx = (mrb_evt_http_server*)http_request_server_userdata(request);
  mrb_value mrbrequest = mrb_obj_value(
    Data_Wrap_Struct(mrbctx->mrb, reqclass, &mrb_evt_http_request_type, request)
  );
  mrb_funcall(mrbctx->mrb, mrbctx->server, "on_request", 1, mrbrequest);
}

static mrb_value server_init(mrb_state* mrb, mrb_value self) {
  mrb_int port;
  mrb_get_args(mrb, "i", &port);
  struct http_server_s* server = http_server_init(port, handle_request);
  mrb_evt_http_server* mrbctx = malloc(sizeof(mrb_evt_http_server));
  mrbctx->server = self;
  mrbctx->mrb = mrb;
  http_server_set_userdata(server, mrbctx);
  DATA_TYPE(self) = &mrb_evt_http_server_type;
  DATA_PTR(self) = server;
  return self;
}

static mrb_value server_listen(mrb_state* mrb, mrb_value self) {
  http_server_listen(DATA_PTR(self));
  return self;
}

// *** mrbgems integration ***

void mrb_mruby_async_http_server_gem_init(mrb_state* mrb) {
  struct RClass* m = mrb_define_module(mrb, "AsyncHttpServer");
  struct RClass* c = mrb_define_class_under(mrb, m, "Server", mrb->object_class);
  reqclass = mrb_define_class_under(mrb, m, "Request", mrb->object_class);
  struct RClass* res = mrb_define_class_under(mrb, m, "Response", mrb->object_class);
  MRB_SET_INSTANCE_TT(c, MRB_TT_DATA);
  MRB_SET_INSTANCE_TT(reqclass, MRB_TT_DATA);
  MRB_SET_INSTANCE_TT(res, MRB_TT_DATA);
  mrb_define_method(mrb, c, "initialize", server_init, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, c, "listen", server_listen, MRB_ARGS_NONE());

  mrb_define_method(mrb, reqclass, "respond", request_respond, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, reqclass, "method", request_method, MRB_ARGS_NONE());
  mrb_define_method(mrb, reqclass, "target", request_target, MRB_ARGS_NONE());
  mrb_define_method(mrb, reqclass, "body", request_body, MRB_ARGS_NONE());
  mrb_define_method(mrb, reqclass, "header", request_header, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, reqclass, "streamed?", request_streamed, MRB_ARGS_NONE());
  mrb_define_method(mrb, reqclass, "each_header", request_each_header, MRB_ARGS_BLOCK());
  mrb_define_method(mrb, reqclass, "end_chunk", request_chunk_end, MRB_ARGS_NONE());
  mrb_define_method(mrb, reqclass, "respond_chunk", request_respond_chunk, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, reqclass, "read_chunk", request_read_chunk, MRB_ARGS_BLOCK());

  mrb_define_method(mrb, res, "initialize", response_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, res, "status=", response_set_status, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, res, "body=", response_set_body, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, res, "set_header", response_set_header, MRB_ARGS_REQ(2));
}

void mrb_mruby_async_http_server_gem_final(mrb_state* mrb) {
}
