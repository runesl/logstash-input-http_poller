# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "logstash/plugin_mixins/http_client"
require "socket" # for Socket.gethostname
require "manticore"
require "rufus/scheduler"

class LogStash::Inputs::HTTP_Poller < LogStash::Inputs::Base
  include LogStash::PluginMixins::HttpClient

  config_name "http_poller"

  default :codec, "json"

  # A Hash of urls in this format : `"name" => "url"`.
  # The name and the url will be passed in the outputed event
  config :urls, :validate => :hash, :required => true

  # Schedule of when to periodically poll from the urls
  # Format: A hash with
  #   + key: "cron" | "every" | "in" | "at"
  #   + value: string
  # Examples:
  #   a) { "every" => "1h" }
  #   b) { "cron" => "* * * * * UTC" }
  # See: rufus/scheduler for details about different schedule options and value string format
  config :schedule, :validate => :hash, :required => true

  # Define the target field for placing the received data. If this setting is omitted, the data will be stored at the root (top level) of the event.
  config :target, :validate => :string

  # If you'd like to work with the request/response metadata.
  # Set this value to the name of the field you'd like to store a nested
  # hash of metadata.
  config :metadata_target, :validate => :string, :default => '@metadata'

  # Choose if you want to emit events on non-2xx http responses. If set to false, such responses will instead be logged
  # as warnings
  config :eventify_http_failures, :validate => :boolean, :default => true

  # Contains these elements:
  # name: the filename of the state file
  # initial_value: If the state file does not exist, it will be created with this value.
  # update_function: After a successful http call, this ruby expression is evaluated to generate the next version of state
  #                  in the state_file. Inputs provided: last_event, state
  # poll_condition_function: <optional> A ruby expression that must evaluate to 'true' for the poll to take place.
  #     Example: "poll_state.to_i < Time.now.to_i"
  config :state_file, :validate => :hash

  public
  Schedule_types = %w(cron every at in)
  def register
    @host = Socket.gethostname.force_encoding(Encoding::UTF_8)

    @logger.info("Registering http_poller Input", :type => @type, :schedule => @schedule, :timeout => @timeout)

    setup_requests!
    validate_state_file_config if @state_file
  end

  def stop
    Stud.stop!(@interval_thread) if @interval_thread
    @scheduler.stop if @scheduler
  end

  private
  def setup_requests!
    @requests = Hash[@urls.map {|name, url| [name, normalize_request(url)] }]
  end

  private
  def normalize_request(url_or_spec)
    if url_or_spec.is_a?(String)
      res = [:get, url_or_spec]
    elsif url_or_spec.is_a?(Hash)
      # The client will expect keys / values
      spec = Hash[url_or_spec.clone.map {|k,v| [k.to_sym, v] }] # symbolize keys

      # method and url aren't really part of the options, so we pull them out
      method = (spec.delete(:method) || :get).to_sym.downcase
      url = spec.delete(:url)

      # Manticore wants auth options that are like {:auth => {:user => u, :pass => p}}
      # We allow that because earlier versions of this plugin documented that as the main way to
      # to do things, but now prefer top level "user", and "password" options
      # So, if the top level user/password are defined they are moved to the :auth key for manticore
      # if those attributes are already in :auth they still need to be transformed to symbols
      auth = spec[:auth]
      user = spec.delete(:user) || (auth && auth["user"])
      password = spec.delete(:password) || (auth && auth["password"])

      if user.nil? ^ password.nil?
        raise LogStash::ConfigurationError, "'user' and 'password' must both be specified for input HTTP poller!"
      end

      if user && password
        spec[:auth] = {
          user: user,
          pass: password,
          eager: true
        }
      end
      res = [method, url, spec]
    else
      raise LogStash::ConfigurationError, "Invalid URL or request spec: '#{url_or_spec}', expected a String or Hash!"
    end

    validate_request!(url_or_spec, res)
    res
  end

  private
  def validate_request!(url_or_spec, request)
    method, url, spec = request

    raise LogStash::ConfigurationError, "Invalid URL #{url}" unless URI::DEFAULT_PARSER.regexp[:ABS_URI].match(url.gsub(/\{(?<expression>.*?poll_state.*?)\}/) {''})

    raise LogStash::ConfigurationError, "No URL provided for request! #{url_or_spec}" unless url
    if spec && spec[:auth]
      if !spec[:auth][:user]
        raise LogStash::ConfigurationError, "Auth was specified, but 'user' was not!"
      end
      if !spec[:auth][:pass]
        raise LogStash::ConfigurationError, "Auth was specified, but 'password' was not!"
      end
    end

    request
  end

  private
  def validate_state_file_config()
    raise LogStash::ConfigurationError, "No 'name' provided inside state_file => {...} !" unless @state_file["name"]
    raise LogStash::ConfigurationError, "No 'update_function' provided inside state_file  => {...} !" unless @state_file["update_function"]
  end

  public
  def run(queue)
    setup_schedule(queue)
  end

  def setup_schedule(queue)
    #schedule hash must contain exactly one of the allowed keys
    msg_invalid_schedule = "Invalid config. schedule hash must contain " +
      "exactly one of the following keys - cron, at, every or in"
    raise Logstash::ConfigurationError, msg_invalid_schedule if @schedule.keys.length !=1
    schedule_type = @schedule.keys.first
    schedule_value = @schedule[schedule_type]
    raise LogStash::ConfigurationError, msg_invalid_schedule unless Schedule_types.include?(schedule_type)

    @scheduler = Rufus::Scheduler.new(:max_work_threads => 1)
    #as of v3.0.9, :first_in => :now doesn't work. Use the following workaround instead
    opts = schedule_type == "every" ? { :first_in => 0.01 } : {}
    @scheduler.send(schedule_type, schedule_value, opts) { run_once(queue) }
    @scheduler.join
  end

  # Despite it's name, this method is called on each poll
  def run_once(queue)
    state = read_state
    if @state_file && !evaluate_poll_condition(state)
        @logger.debug? && @logger.debug("Skipping poll due to poll condition")
        return
    end

    @requests.each do |name, request|
      request = update_request_with_poll_state(request, state) if @state_file
      request_async(queue, name, request, state)
    end

    client.execute!
  end

  def read_state
    if not File.file?(@state_file["name"])
        File.write(@state_file["name"], @state_file["initial_value"])
        @logger.debug? && @logger.debug("Wrote initial value to state_file", :state_file => @state_file)
    end
    state = File.read(@state_file["name"])
  end

  # Evaluate poll_state expressions in url and body.
  # A poll_state expression must be on the form '(<ruby-code>)', where <ruby-code> contains at least one reference to
  # 'poll_state' variable. Example: (poll_state.to_i+1)
  def update_request_with_poll_state(static_request, poll_state)
    @logger.debug("update_request_with_poll_state", :state => poll_state, :static_request => static_request)
    new_url = static_request[1].gsub(/\{(?<expression>.*?poll_state.*?)\}/) { eval($~[:expression]).to_s }

    new_spec = static_request[2].clone
    if static_request[2] != nil && static_request[2].key?(:body)
        new_spec[:body] = static_request[2][:body].gsub(/\{(?<expression>.*?poll_state.*?)\}/) { eval($~[:expression]).to_s }
        @logger.debug("updated body", :state => poll_state, :new_spec => new_spec)
    end
    [static_request[0], new_url, new_spec]
  end

  private
  def request_async(queue, name, request, state)
    @logger.debug? && @logger.debug("Fetching URL", :name => name, :url => request)
    started = Time.now

    method, *request_opts = request
    client.async.send(method, *request_opts).
      on_success {|response| handle_success(queue, name, request, response, Time.now - started, state)}.
      on_failure {|exception|
      handle_failure(queue, name, request, exception, Time.now - started)
    }
  end

  private
  def handle_success(queue, name, request, response, execution_time, state)
    # Manticore's definition of "success" includes requests that return non-2xx response codes.
    # All such responses need to be handled here.
    if response.code > 299 && (!@eventify_http_failures) && @logger.warn?
       @logger.warn("Non-successful http response received",
                                      :url => request,
                                      :response => response)
    else
      body = response.body
      # If there is a usable response. HEAD requests are `nil` and empty get
      # responses come up as "" which will cause the codec to not yield anything
      event = nil
      if body && body.size > 0
        decode_and_flush(@codec, body) do |decoded|
          event = @target ? LogStash::Event.new(@target => decoded.to_hash) : decoded
          handle_decoded_event(queue, name, request, response, event, execution_time)
        end
      else
        event = ::LogStash::Event.new
        handle_decoded_event(queue, name, request, response, event, execution_time)
      end
      update_state_file(event, state) if @state_file
    end
  end

  def update_state_file(last_event, poll_state)
    if last_event != nil
        last_event = last_event.to_hash
    end
    @logger.debug? && @logger.debug("update_state_file.", :update_function => @state_file["update_function"],
        :poll_state => poll_state, :last_event => last_event)
    begin
        poll_state = eval(@state_file["update_function"])
        File.write(@state_file["name"], poll_state)
    rescue SyntaxError => se
        @logger.warn("Your http_poller update_function failed with SyntaxError.", :se => se,
            :update_function => update_function)
    end
  end

  # Return true if poll is to be performed, false if it is to be skipped
  def evaluate_poll_condition(poll_state)
  pc_fun = @state_file["poll_condition_function"]
    return true unless pc_fun
    @logger.debug? && @logger.debug("evaluate_poll_condition.", :poll_condition_function => pc_fun,
        :poll_state => poll_state)
    begin
        eval(pc_fun)
    rescue SyntaxError => se
        @logger.warn("Your poll_condition_function failed with SyntaxError.", :se => se,
            :poll_condition_function => pc_fun)
    end
  end

  private
  def decode_and_flush(codec, body, &yielder)
    codec.decode(body, &yielder)
    codec.flush(&yielder)
  end

  private
  def handle_decoded_event(queue, name, request, response, event, execution_time)
    apply_metadata(event, name, request, response, execution_time)
    decorate(event)
    queue << event
  rescue StandardError, java.lang.Exception => e
    @logger.error? && @logger.error("Error eventifying response!",
                                    :exception => e,
                                    :exception_message => e.message,
                                    :name => name,
                                    :url => request,
                                    :response => response
    )
  end

  private
  # Beware, on old versions of manticore some uncommon failures are not handled
  def handle_failure(queue, name, request, exception, execution_time)
    failure =  {
        "request" => structure_request(request),
        "name" => name,
        "error" => exception.to_s,
        "backtrace" => exception.backtrace,
        "runtime_seconds" => execution_time
    }

    if !@eventify_http_failures && @logger.warn?
       @logger.warn("http failure", :failure => failure)
   else
        event = LogStash::Event.new
        apply_metadata(event, name, request)

        event.tag("_http_request_failure")

        # This is also in the metadata, but we send it anyone because we want this
        # persisted by default, whereas metadata isn't. People don't like mysterious errors
        event.set("http_request_failure", failure)

        queue << event
      rescue StandardError, java.lang.Exception => e
          @logger.error? && @logger.error("Cannot read URL or send the error as an event!",
                                          :exception => e,
                                          :exception_message => e.message,
                                          :exception_backtrace => e.backtrace,
                                          :name => name)

          # If we are running in debug mode we can display more information about the
          # specific request which could give more details about the connection.
          @logger.debug? && @logger.debug("Cannot read URL or send the error as an event!",
                                          :exception => e,
                                          :exception_message => e.message,
                                          :exception_backtrace => e.backtrace,
                                          :name => name,
                                          :url => request)
  end

  private
  def apply_metadata(event, name, request, response=nil, execution_time=nil)
    return unless @metadata_target
    event.set(@metadata_target, event_metadata(name, request, response, execution_time))
  end

  private
  def event_metadata(name, request, response=nil, execution_time=nil)
    m = {
        "name" => name,
        "host" => @host,
        "request" => structure_request(request),
      }

    m["runtime_seconds"] = execution_time

    if response
      m["code"] = response.code
      m["response_headers"] = response.headers
      m["response_message"] = response.message
      m["times_retried"] = response.times_retried
    end

    m
  end

  private
  # Turn [method, url, spec] requests into a hash for friendlier logging / ES indexing
  def structure_request(request)
    method, url, spec = request
    # Flatten everything into the 'spec' hash, also stringify any keys to normalize
    Hash[(spec||{}).merge({
      "method" => method.to_s,
      "url" => url,
    }).map {|k,v| [k.to_s, k.to_s  =~ /auth/i ? "<auth-stripped>": v]}]
  end
end
