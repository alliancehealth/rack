require_relative 'spec_helper'

context "Rack::Utils" do
  specify "should escape correctly" do
    Rack::Utils.escape("fo<o>bar").should == "fo%3Co%3Ebar"
    Rack::Utils.escape("a space").should == "a+space"
    Rack::Utils.escape("q1!2\"'w$5&7/z8)?\\").
      should == "q1%212%22%27w%245%267%2Fz8%29%3F%5C"
  end

  specify "should escape correctly for multibyte characters" do
    matz_name = "\xE3\x81\xBE\xE3\x81\xA4\xE3\x82\x82\xE3\x81\xA8".unpack("a*")[0] # Matsumoto
    matz_name.force_encoding("UTF-8") if matz_name.respond_to? :force_encoding
    Rack::Utils.escape(matz_name).should == '%E3%81%BE%E3%81%A4%E3%82%82%E3%81%A8'
    matz_name_sep = "\xE3\x81\xBE\xE3\x81\xA4 \xE3\x82\x82\xE3\x81\xA8".unpack("a*")[0] # Matsu moto
    matz_name_sep.force_encoding("UTF-8") if matz_name_sep.respond_to? :force_encoding
    Rack::Utils.escape(matz_name_sep).should == '%E3%81%BE%E3%81%A4+%E3%82%82%E3%81%A8'
  end

  specify "should unescape correctly" do
    Rack::Utils.unescape("fo%3Co%3Ebar").should == "fo<o>bar"
    Rack::Utils.unescape("a+space").should == "a space"
    Rack::Utils.unescape("a%20space").should == "a space"
    Rack::Utils.unescape("q1%212%22%27w%245%267%2Fz8%29%3F%5C").
      should == "q1!2\"'w$5&7/z8)?\\"
  end

  specify "should parse query strings correctly" do
    Rack::Utils.parse_query("foo=bar").
      should == {"foo" => "bar"}
    Rack::Utils.parse_query("foo=\"bar\"").
      should == {"foo" => "\"bar\""}
    Rack::Utils.parse_query("foo=bar&foo=quux").
      should == {"foo" => ["bar", "quux"]}
    Rack::Utils.parse_query("foo=1&bar=2").
      should == {"foo" => "1", "bar" => "2"}
    Rack::Utils.parse_query("my+weird+field=q1%212%22%27w%245%267%2Fz8%29%3F").
      should == {"my weird field" => "q1!2\"'w$5&7/z8)?"}
    Rack::Utils.parse_query("foo%3Dbaz=bar").should == {"foo=baz" => "bar"}
  end

  specify "should raise an exception if the params are too deep" do
    len = Rack::Utils.param_depth_limit

    lambda {
      Rack::Utils.parse_nested_query("foo#{"[a]" * len}=bar")
    }.should raise_error(RangeError)

    lambda {
      Rack::Utils.parse_nested_query("foo#{"[a]" * (len - 1)}=bar")
    }.should_not raise_error
  end

  specify "should parse nested query strings correctly" do
    Rack::Utils.parse_nested_query("foo").
      should == {"foo" => nil}
    Rack::Utils.parse_nested_query("foo=").
      should == {"foo" => ""}
    Rack::Utils.parse_nested_query("foo=bar").
      should == {"foo" => "bar"}
    Rack::Utils.parse_nested_query("foo=\"bar\"").
      should == {"foo" => "\"bar\""}

    Rack::Utils.parse_nested_query("foo=bar&foo=quux").
      should == {"foo" => "quux"}
    Rack::Utils.parse_nested_query("foo&foo=").
      should == {"foo" => ""}
    Rack::Utils.parse_nested_query("foo=1&bar=2").
      should == {"foo" => "1", "bar" => "2"}
    Rack::Utils.parse_nested_query("&foo=1&&bar=2").
      should == {"foo" => "1", "bar" => "2"}
    Rack::Utils.parse_nested_query("foo&bar=").
      should == {"foo" => nil, "bar" => ""}
    Rack::Utils.parse_nested_query("foo=bar&baz=").
      should == {"foo" => "bar", "baz" => ""}
    Rack::Utils.parse_nested_query("my+weird+field=q1%212%22%27w%245%267%2Fz8%29%3F").
      should == {"my weird field" => "q1!2\"'w$5&7/z8)?"}

    Rack::Utils.parse_nested_query("foo[]").
      should == {"foo" => [nil]}
    Rack::Utils.parse_nested_query("foo[]=").
      should == {"foo" => [""]}
    Rack::Utils.parse_nested_query("foo[]=bar").
      should == {"foo" => ["bar"]}

    Rack::Utils.parse_nested_query("foo[]=1&foo[]=2").
      should == {"foo" => ["1", "2"]}
    Rack::Utils.parse_nested_query("foo=bar&baz[]=1&baz[]=2&baz[]=3").
      should == {"foo" => "bar", "baz" => ["1", "2", "3"]}
    Rack::Utils.parse_nested_query("foo[]=bar&baz[]=1&baz[]=2&baz[]=3").
      should == {"foo" => ["bar"], "baz" => ["1", "2", "3"]}

    Rack::Utils.parse_nested_query("x[y][z]=1").
      should == {"x" => {"y" => {"z" => "1"}}}
    Rack::Utils.parse_nested_query("x[y][z][]=1").
      should == {"x" => {"y" => {"z" => ["1"]}}}
    Rack::Utils.parse_nested_query("x[y][z]=1&x[y][z]=2").
      should == {"x" => {"y" => {"z" => "2"}}}
    Rack::Utils.parse_nested_query("x[y][z][]=1&x[y][z][]=2").
      should == {"x" => {"y" => {"z" => ["1", "2"]}}}

    Rack::Utils.parse_nested_query("x[y][][z]=1").
      should == {"x" => {"y" => [{"z" => "1"}]}}
    Rack::Utils.parse_nested_query("x[y][][z][]=1").
      should == {"x" => {"y" => [{"z" => ["1"]}]}}
    Rack::Utils.parse_nested_query("x[y][][z]=1&x[y][][w]=2").
      should == {"x" => {"y" => [{"z" => "1", "w" => "2"}]}}

    Rack::Utils.parse_nested_query("x[y][][v][w]=1").
      should == {"x" => {"y" => [{"v" => {"w" => "1"}}]}}
    Rack::Utils.parse_nested_query("x[y][][z]=1&x[y][][v][w]=2").
      should == {"x" => {"y" => [{"z" => "1", "v" => {"w" => "2"}}]}}

    Rack::Utils.parse_nested_query("x[y][][z]=1&x[y][][z]=2").
      should == {"x" => {"y" => [{"z" => "1"}, {"z" => "2"}]}}
    Rack::Utils.parse_nested_query("x[y][][z]=1&x[y][][w]=a&x[y][][z]=2&x[y][][w]=3").
      should == {"x" => {"y" => [{"z" => "1", "w" => "a"}, {"z" => "2", "w" => "3"}]}}

    lambda { Rack::Utils.parse_nested_query("x[y]=1&x[y]z=2") }.
      should raise_error(TypeError, "expected Hash (got String) for param `y'")

    lambda { Rack::Utils.parse_nested_query("x[y]=1&x[]=1") }.
      should raise_error(TypeError, "expected Array (got Hash) for param `x'")

    lambda { Rack::Utils.parse_nested_query("x[y]=1&x[y][][w]=2") }.
      should raise_error(TypeError, "expected Array (got String) for param `y'")
  end

  specify "should build query strings correctly" do
    Rack::Utils.build_query("foo" => "bar").should == "foo=bar"
    Rack::Utils.build_query("foo" => ["bar", "quux"]).
      should == "foo=bar&foo=quux"
    Rack::Utils.build_query("foo" => "1", "bar" => "2").
      should == "foo=1&bar=2"
    Rack::Utils.build_query("my weird field" => "q1!2\"'w$5&7/z8)?").
      should == "my+weird+field=q1%212%22%27w%245%267%2Fz8%29%3F"
  end

  specify "should build nested query strings correctly" do
    Rack::Utils.build_nested_query("foo" => nil).should == "foo"
    Rack::Utils.build_nested_query("foo" => "").should == "foo="
    Rack::Utils.build_nested_query("foo" => "bar").should == "foo=bar"

    Rack::Utils.build_nested_query("foo" => "1", "bar" => "2").
      should == "foo=1&bar=2"
    Rack::Utils.build_nested_query("my weird field" => "q1!2\"'w$5&7/z8)?").
      should == "my+weird+field=q1%212%22%27w%245%267%2Fz8%29%3F"

    Rack::Utils.build_nested_query("foo" => [nil]).
      should == "foo[]"
    Rack::Utils.build_nested_query("foo" => [""]).
      should == "foo[]="
    Rack::Utils.build_nested_query("foo" => ["bar"]).
      should == "foo[]=bar"

    # The ordering of the output query string is unpredictable with 1.8's
    # unordered hash. Test that build_nested_query performs the inverse
    # function of parse_nested_query.
    [{"foo" => nil, "bar" => ""},
     {"foo" => "bar", "baz" => ""},
     {"foo" => ["1", "2"]},
     {"foo" => "bar", "baz" => ["1", "2", "3"]},
     {"foo" => ["bar"], "baz" => ["1", "2", "3"]},
     {"foo" => ["1", "2"]},
     {"foo" => "bar", "baz" => ["1", "2", "3"]},
     {"x" => {"y" => {"z" => "1"}}},
     {"x" => {"y" => {"z" => ["1"]}}},
     {"x" => {"y" => {"z" => ["1", "2"]}}},
     {"x" => {"y" => [{"z" => "1"}]}},
     {"x" => {"y" => [{"z" => ["1"]}]}},
     {"x" => {"y" => [{"z" => "1", "w" => "2"}]}},
     {"x" => {"y" => [{"v" => {"w" => "1"}}]}},
     {"x" => {"y" => [{"z" => "1", "v" => {"w" => "2"}}]}},
     {"x" => {"y" => [{"z" => "1"}, {"z" => "2"}]}},
     {"x" => {"y" => [{"z" => "1", "w" => "a"}, {"z" => "2", "w" => "3"}]}}
    ].each { |params|
      qs = Rack::Utils.build_nested_query(params)
      Rack::Utils.parse_nested_query(qs).should == params
    }

    lambda { Rack::Utils.build_nested_query("foo=bar") }.
      should raise_error(ArgumentError, "value must be a Hash")
  end

  specify "should figure out which encodings are acceptable" do
    helper = lambda do |a, b|
      request = Rack::Request.new(Rack::MockRequest.env_for("", "HTTP_ACCEPT_ENCODING" => a))
      Rack::Utils.select_best_encoding(a, b)
    end

    helper.call(%w(), [["x", 1]]).should ==(nil)
    helper.call(%w(identity), [["identity", 0.0]]).should ==(nil)
    helper.call(%w(identity), [["*", 0.0]]).should ==(nil)

    helper.call(%w(identity), [["compress", 1.0], ["gzip", 1.0]]).should ==("identity")

    helper.call(%w(compress gzip identity), [["compress", 1.0], ["gzip", 1.0]]).should ==("compress")
    helper.call(%w(compress gzip identity), [["compress", 0.5], ["gzip", 1.0]]).should ==("gzip")

    helper.call(%w(foo bar identity), []).should ==("identity")
    helper.call(%w(foo bar identity), [["*", 1.0]]).should ==("foo")
    helper.call(%w(foo bar identity), [["*", 1.0], ["foo", 0.9]]).should ==("bar")

    helper.call(%w(foo bar identity), [["foo", 0], ["bar", 0]]).should ==("identity")
    helper.call(%w(foo bar baz identity), [["*", 0], ["identity", 0.1]]).should ==("identity")
  end

  specify "should return the bytesize of String" do
    Rack::Utils.bytesize("FOO\xE2\x82\xAC").should == 6
  end

  specify "should perform constant time string comparison" do
    Rack::Utils.secure_compare('a', 'a').should == true
    Rack::Utils.secure_compare('a', 'b').should == false
  end

  specify "should return status code for integer" do
    Rack::Utils.status_code(200).should == 200
  end

  specify "should return status code for string" do
    Rack::Utils.status_code("200").should == 200
  end

  specify "should return status code for symbol" do
    Rack::Utils.status_code(:ok).should == 200
  end
end

context "Rack::Utils::HeaderHash" do
  specify "should retain header case" do
    h = Rack::Utils::HeaderHash.new("Content-MD5" => "d5ff4e2a0 ...")
    h['ETag'] = 'Boo!'
    h.to_hash.should == {"Content-MD5" => "d5ff4e2a0 ...", "ETag" => 'Boo!'}
  end

  specify "should check existence of keys case insensitively" do
    h = Rack::Utils::HeaderHash.new("Content-MD5" => "d5ff4e2a0 ...")
    h.should include 'content-md5'
    h.should_not include 'ETag'
  end

  specify "should merge case-insensitively" do
    h = Rack::Utils::HeaderHash.new("ETag" => 'HELLO', "content-length" => '123')
    merged = h.merge("Etag" => 'WORLD', 'Content-Length' => '321', "Foo" => 'BAR')
    merged.should == {"Etag"=>'WORLD', "Content-Length"=>'321', "Foo"=>'BAR'}
  end

  specify "should overwrite case insensitively and assume the new key's case" do
    h = Rack::Utils::HeaderHash.new("Foo-Bar" => "baz")
    h["foo-bar"] = "bizzle"
    h["FOO-BAR"].should == "bizzle"
    h.length.should == 1
    h.to_hash.should == {"foo-bar" => "bizzle"}
  end

  specify "should be converted to real Hash" do
    h = Rack::Utils::HeaderHash.new("foo" => "bar")
    h.to_hash.should be_an_instance_of Hash
  end

  specify "should convert Array values to Strings when converting to Hash" do
    h = Rack::Utils::HeaderHash.new("foo" => ["bar", "baz"])
    h.to_hash.should ==({ "foo" => "bar\nbaz" })
  end

  specify "should replace hashes correctly" do
    h = Rack::Utils::HeaderHash.new("Foo-Bar" => "baz")
    j = {"foo" => "bar"}
    h.replace(j)
    h["foo"].should == "bar"
  end

  specify "should be able to delete the given key case-sensitively" do
    h = Rack::Utils::HeaderHash.new("foo" => "bar")
    h.delete("foo")
    h["foo"].should be_nil
    h["FOO"].should be_nil
  end

  specify "should be able to delete the given key case-insensitively" do
    h = Rack::Utils::HeaderHash.new("foo" => "bar")
    h.delete("FOO")
    h["foo"].should be_nil
    h["FOO"].should be_nil
  end

  specify "should return the deleted value when #delete is called on an existing key" do
    h = Rack::Utils::HeaderHash.new("foo" => "bar")
    h.delete("Foo").should ==("bar")
  end

  specify "should return nil when #delete is called on a non-existant key" do
    h = Rack::Utils::HeaderHash.new("foo" => "bar")
    h.delete("Hello").should be_nil
  end

  specify "should avoid unnecessary object creation if possible" do
    a = Rack::Utils::HeaderHash.new("foo" => "bar")
    b = Rack::Utils::HeaderHash.new(a)
    b.object_id.should equal(a.object_id)
    b.should equal(a)
  end

  specify "should convert Array values to Strings when responding to #each" do
    h = Rack::Utils::HeaderHash.new("foo" => ["bar", "baz"])
    h.each do |k,v|
      k.should ==("foo")
      v.should ==("bar\nbaz")
    end
  end

end

context "Rack::Utils::Context" do
  class ContextTest
    attr_reader :app
    def initialize app; @app=app; end
    def call env; context env; end
    def context env, app=@app; app.call(env); end
  end
  test_target1 = proc{|e| e.to_s+' world' }
  test_target2 = proc{|e| e.to_i+2 }
  test_target3 = proc{|e| nil }
  test_target4 = proc{|e| [200,{'Content-Type'=>'text/plain', 'Content-Length'=>'0'},['']] }
  test_app = ContextTest.new test_target4

  specify "should set context correctly" do
    test_app.app.should equal test_target4
    c1 = Rack::Utils::Context.new(test_app, test_target1)
    c1.for.should equal test_app
    c1.app.should equal test_target1
    c2 = Rack::Utils::Context.new(test_app, test_target2)
    c2.for.should equal test_app
    c2.app.should equal test_target2
  end

  specify "should alter app on recontexting" do
    c1 = Rack::Utils::Context.new(test_app, test_target1)
    c2 = c1.recontext(test_target2)
    c2.for.should equal test_app
    c2.app.should equal test_target2
    c3 = c2.recontext(test_target3)
    c3.for.should equal test_app
    c3.app.should equal test_target3
  end

  specify "should run different apps" do
    c1 = Rack::Utils::Context.new test_app, test_target1
    c2 = c1.recontext test_target2
    c3 = c2.recontext test_target3
    c4 = c3.recontext test_target4
    a4 = Rack::Lint.new c4
    a5 = Rack::Lint.new test_app
    r1 = c1.call('hello')
    r1.should == 'hello world'
    r2 = c2.call(2)
    r2.should equal 4
    r3 = c3.call(:misc_symbol)
    r3.should be_nil
    r4 = Rack::MockRequest.new(a4).get('/')
    r4.status.should be 200
    r5 = Rack::MockRequest.new(a5).get('/')
    r5.status.should be 200
    r4.body.should == r5.body
  end
end

context "Rack::Utils::Multipart" do
  specify "should return nil if content type is not multipart" do
    env = Rack::MockRequest.env_for("/",
            "CONTENT_TYPE" => 'application/x-www-form-urlencoded')
    Rack::Utils::Multipart.parse_multipart(env).should equal nil
  end

  specify "should parse multipart upload with text file" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:text))
    params = Rack::Utils::Multipart.parse_multipart(env)
    params["submit-name"].should == "Larry"
    params["files"][:type].should == "text/plain"
    params["files"][:filename].should == "file1.txt"
    params["files"][:head].should == "Content-Disposition: form-data; " +
      "name=\"files\"; filename=\"file1.txt\"\r\n" +
      "Content-Type: text/plain\r\n"
    params["files"][:name].should == "files"
    params["files"][:tempfile].read.should == "contents"
  end

  specify "should parse multipart upload with nested parameters" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:nested))
    params = Rack::Utils::Multipart.parse_multipart(env)
    params["foo"]["submit-name"].should == "Larry"
    params["foo"]["files"][:type].should == "text/plain"
    params["foo"]["files"][:filename].should == "file1.txt"
    params["foo"]["files"][:head].should == "Content-Disposition: form-data; " +
      "name=\"foo[files]\"; filename=\"file1.txt\"\r\n" +
      "Content-Type: text/plain\r\n"
    params["foo"]["files"][:name].should == "foo[files]"
    params["foo"]["files"][:tempfile].read.should == "contents"
  end

  specify "should parse multipart upload with binary file" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:binary))
    params = Rack::Utils::Multipart.parse_multipart(env)
    params["submit-name"].should == "Larry"
    params["files"][:type].should == "image/png"
    params["files"][:filename].should == "rack-logo.png"
    params["files"][:head].should == "Content-Disposition: form-data; " +
      "name=\"files\"; filename=\"rack-logo.png\"\r\n" +
      "Content-Type: image/png\r\n"
    params["files"][:name].should == "files"
    params["files"][:tempfile].read.length.should == 26473
  end

  specify "should parse multipart upload with empty file" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:empty))
    params = Rack::Utils::Multipart.parse_multipart(env)
    params["submit-name"].should == "Larry"
    params["files"][:type].should == "text/plain"
    params["files"][:filename].should == "file1.txt"
    params["files"][:head].should == "Content-Disposition: form-data; " +
      "name=\"files\"; filename=\"file1.txt\"\r\n" +
      "Content-Type: text/plain\r\n"
    params["files"][:name].should == "files"
    params["files"][:tempfile].read.should == ""
  end

  specify "should parse multipart upload with filename with semicolons" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:semicolon))
    params = Rack::Utils::Multipart.parse_multipart(env)
    params["files"][:type].should == "text/plain"
    params["files"][:filename].should == "fi;le1.txt"
    params["files"][:head].should == "Content-Disposition: form-data; " +
      "name=\"files\"; filename=\"fi;le1.txt\"\r\n" +
      "Content-Type: text/plain\r\n"
    params["files"][:name].should == "files"
    params["files"][:tempfile].read.should == "contents"
  end

  specify "should not include file params if no file was selected" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:none))
    params = Rack::Utils::Multipart.parse_multipart(env)
    params["submit-name"].should == "Larry"
    params["files"].should equal nil
    params.keys.should_not include "files"
  end

  specify "should parse IE multipart upload and clean up filename" do
    env = Rack::MockRequest.env_for("/", multipart_fixture(:ie))
    params = Rack::Utils::Multipart.parse_multipart(env)
    params["files"][:type].should == "text/plain"
    params["files"][:filename].should == "file1.txt"
    params["files"][:head].should == "Content-Disposition: form-data; " +
      "name=\"files\"; " +
      'filename="C:\Documents and Settings\Administrator\Desktop\file1.txt"' +
      "\r\nContent-Type: text/plain\r\n"
    params["files"][:name].should == "files"
    params["files"][:tempfile].read.should == "contents"
  end

  specify "rewinds input after parsing upload" do
    options = multipart_fixture(:text)
    input = options[:input]
    env = Rack::MockRequest.env_for("/", options)
    params = Rack::Utils::Multipart.parse_multipart(env)
    params["submit-name"].should == "Larry"
    params["files"][:filename].should == "file1.txt"
    input.read.length.should equal 197
  end

  specify "builds multipart body" do
    files = Rack::Utils::Multipart::UploadedFile.new(multipart_file("file1.txt"))
    data  = Rack::Utils::Multipart.build_multipart("submit-name" => "Larry", "files" => files)

    options = {
      "CONTENT_TYPE" => "multipart/form-data; boundary=AaB03x",
      "CONTENT_LENGTH" => data.length.to_s,
      :input => StringIO.new(data)
    }
    env = Rack::MockRequest.env_for("/", options)
    params = Rack::Utils::Multipart.parse_multipart(env)
    params["submit-name"].should == "Larry"
    params["files"][:filename].should == "file1.txt"
    params["files"][:tempfile].read.should == "contents"
  end

  specify "builds nested multipart body" do
    files = Rack::Utils::Multipart::UploadedFile.new(multipart_file("file1.txt"))
    data  = Rack::Utils::Multipart.build_multipart("people" => [{"submit-name" => "Larry", "files" => files}])

    options = {
      "CONTENT_TYPE" => "multipart/form-data; boundary=AaB03x",
      "CONTENT_LENGTH" => data.length.to_s,
      :input => StringIO.new(data)
    }
    env = Rack::MockRequest.env_for("/", options)
    params = Rack::Utils::Multipart.parse_multipart(env)
    params["people"][0]["submit-name"].should == "Larry"
    params["people"][0]["files"][:filename].should == "file1.txt"
    params["people"][0]["files"][:tempfile].read.should == "contents"
  end

  specify "can parse fields that end at the end of the buffer" do
    input = File.read(multipart_file("bad_robots"))

    req = Rack::Request.new Rack::MockRequest.env_for("/",
                      "CONTENT_TYPE" => "multipart/form-data, boundary=1yy3laWhgX31qpiHinh67wJXqKalukEUTvqTzmon",
                      "CONTENT_LENGTH" => input.size,
                      :input => input)

    req.POST['file.path'].should == "/var/tmp/uploads/4/0001728414"
    req.POST['addresses'].should_not equal nil
  end

  specify "builds complete params with the chunk size of 16384 slicing exactly on boundary" do
    data = File.open(multipart_file("fail_16384_nofile")) { |f| f.read }.gsub(/\n/, "\r\n")
    options = {
      "CONTENT_TYPE" => "multipart/form-data; boundary=----WebKitFormBoundaryWsY0GnpbI5U7ztzo",
      "CONTENT_LENGTH" => data.length.to_s,
      :input => StringIO.new(data)
    }
    env = Rack::MockRequest.env_for("/", options)
    params = Rack::Utils::Multipart.parse_multipart(env)

    params.should_not equal nil
    params.keys.should include "AAAAAAAAAAAAAAAAAAA"
    params["AAAAAAAAAAAAAAAAAAA"].keys.should include "PLAPLAPLA_MEMMEMMEMM_ATTRATTRER"
    params["AAAAAAAAAAAAAAAAAAA"]["PLAPLAPLA_MEMMEMMEMM_ATTRATTRER"].keys.should include "new"
    params["AAAAAAAAAAAAAAAAAAA"]["PLAPLAPLA_MEMMEMMEMM_ATTRATTRER"]["new"].keys.should include "-2"
    params["AAAAAAAAAAAAAAAAAAA"]["PLAPLAPLA_MEMMEMMEMM_ATTRATTRER"]["new"]["-2"].keys.should include "ba_unit_id"
    params["AAAAAAAAAAAAAAAAAAA"]["PLAPLAPLA_MEMMEMMEMM_ATTRATTRER"]["new"]["-2"]["ba_unit_id"].should == "1017"
  end

  specify "should return nil if no UploadedFiles were used" do
    data = Rack::Utils::Multipart.build_multipart("people" => [{"submit-name" => "Larry", "files" => "contents"}])
    data.should equal nil
  end

  specify "should raise ArgumentError if params is not a Hash" do
    lambda { Rack::Utils::Multipart.build_multipart("foo=bar") }.
      should raise_error(ArgumentError, "value must be a Hash")
  end

  private
    def multipart_fixture(name)
      file = multipart_file(name)
      data = File.open(file, 'rb') { |io| io.read }

      type = "multipart/form-data; boundary=AaB03x"
      length = data.respond_to?(:bytesize) ? data.bytesize : data.size

      { "CONTENT_TYPE" => type,
        "CONTENT_LENGTH" => length.to_s,
        :input => StringIO.new(data) }
    end

    def multipart_file(name)
      File.join(File.dirname(__FILE__), "multipart", name.to_s)
    end
end
