require 'spec_helper'

require 'rack/test'
require 'timecop'

require 'lib/angus-authentication'

describe Rack::Middleware::AngusAuthentication do
  include Rack::Test::Methods

  let(:settings) { { :private_key => private_key, :public_key => public_key,
                     :max_failed_attempts => max_failed_attempts, :use_session => use_session } }
  let(:application) { double(:application) }

  def app
    Rack::Middleware::AngusAuthentication.new(application, settings)
  end

  let(:headers) { {} }

  def make_request
    headers.each { |k,v | header(k, v) }
    get '/authenticated'
  end

  let(:public_key) { 'sadsadasdoi212ekjzXclmn3l24e' }
  let(:private_key) { 'CHANGE ME!!' }
  let(:path_info) { '/authenticated' }
  let(:auth_data) { "#{date.httpdate}\nGET\n#{path_info}" }
  let(:max_failed_attempts) { 3 }
  let(:use_session) { false }

  let(:auth_token) { Digest::SHA1.hexdigest("#{private_key}\n#{auth_data}")  }
  let(:date) { Date.today }

  before { application.stub(:call => [200, {}, '']) }

  describe '#call' do

    context 'when no date header' do
      let(:headers) { { 'X-Baas-Auth' => "#{public_key}:#{auth_token}" } }

      it 'does not invoke the application' do
        make_request

        application.should_not have_received(:call)
      end

      describe 'the response' do

        subject(:response) { make_request; last_response }

        its(:status) { should eq(401) }

      end

      context 'when a excluded regexp' do
        let(:settings) { { :excluded_regexps => %w(authenticated) } }

        it 'invokes the application' do
          make_request

          application.should have_received(:call).once
        end

        describe 'the response' do

          subject(:response) { make_request; last_response }

          its(:status) { should eq(200) }
          its(['X-Baas-Session-Seed']) { should_not be }

        end
      end
    end

    context 'when date header' do
      context 'when no authentication headers' do
        let(:headers) { { 'date' => date.httpdate  } }

        it 'does not invoke the application' do
          make_request

          application.should_not have_received(:call)
        end

        describe 'the response' do

          subject(:response) { make_request; last_response }

          its(:status) { should eq(401) }

        end
      end

      context 'when not using sessions' do
        let(:use_session) { false }

        context 'when invalid authentication data' do
          let(:headers) { { 'date' => date.httpdate,
                            'Authorization' => "#{public_key}:aa#{auth_token}" } }

          it 'does not invoke the application' do
            make_request

            application.should_not have_received(:call)
          end

          describe 'the response' do

            subject(:response) { make_request; last_response }

            its(:status) { should eq(401) }

          end
        end

        context 'when valid authentication headers' do
          let(:headers) { { 'date' => date.httpdate,
                            'Authorization' => "#{public_key}:#{auth_token}" } }

          it 'invokes the application' do
            make_request

            application.should have_received(:call).once
          end

          describe 'the response' do

            subject(:response) { make_request; last_response }

            its(:status) { should eq(200) }

          end

          context 'when a request has already been done' do
            before { make_request }

            it 'invokes the application' do
              make_request

              application.should have_received(:call).twice
            end

            describe 'the response' do

              subject(:response) { make_request; last_response }

              its(:status) { should eq(200) }

            end
          end
        end
      end

      context 'when using sessions' do
        let(:use_session) { true }

        context 'when no session is present' do
          context 'when missing Authentication header' do
            let(:headers) { { 'date' => "#{public_key}",
                              'X-Baas-Auth' => "#{public_key}:#{auth_token}" } }

            it 'does not invoke the application' do
              make_request

              application.should_not have_received(:call)
            end

            describe 'the response' do

              subject(:response) { make_request; last_response }

              its(:status) { should eq(401) }

            end
          end

          context 'when invalid authentication data' do
            let(:headers) { { 'date' => date.httpdate,
                              'Authorization' => "#{public_key}:aa#{auth_token}" } }

            it 'does not invoke the application' do
              make_request

              application.should_not have_received(:call)
            end

            describe 'the response' do

              subject(:response) { make_request; last_response }

              its(:status) { should eq(401) }

            end
          end

          context 'when valid authentication headers' do
            let(:headers) { { 'date' => date.httpdate,
                              'Authorization' => "#{public_key}:#{auth_token}" } }

            it 'invokes the application' do
              make_request

              application.should have_received(:call).once
            end

            describe 'the response' do

              subject(:response) { make_request; last_response }

              its(:status) { should eq(200) }
              its(['X-Baas-Session-Seed']) { should_not be_empty }

            end
          end
        end

        context 'and a session is present' do
          let!(:session_private_key) do
            header('date', date.httpdate)
            header('Authorization', "#{public_key}:#{auth_token}")
            get '/authenticated'
            private_session_key_seed = last_response.header['X-Baas-Session-Seed']

            Digest::SHA1.hexdigest("#{private_key}\n#{private_session_key_seed}")
          end

          context 'when missing Authorization and X-Baas-Auth header' do
            let(:headers) { { 'date' => date.httpdate,
                              'Authorization' => nil } }

            it 'does not invoke the application' do
              make_request

              application.should have_received(:call).once
            end

            describe 'the response' do

              subject(:response) { make_request; last_response }

              its(:status) { should eq(401) }

            end
          end

          context 'when just missing X-Baas-Auth header' do
            let(:headers) { { 'date' => date.httpdate,
                              'Authorization' => "#{public_key}:#{auth_token}" } }

            it 'invokes the application' do
              make_request

              application.should have_received(:call).twice
            end

            describe 'the response' do

              subject(:response) { make_request; last_response }

              its(:status) { should eq(200) }

            end
          end

          context 'when invalid session authentication data' do
            context 'and authentication data missing' do
              let(:headers) { { 'date' => date.httpdate,
                                'X-Baas-Auth' => "#{public_key}:invalid",
                                'Authorization' => nil } }

              it 'does not invoke the application' do
                make_request

                application.should have_received(:call).once
              end

              describe 'the response' do

                subject(:response) { make_request; last_response }

                its(:status) { should eq(401) }

              end
            end

            context 'but authentication data is present' do
              let(:headers) { { 'date' => date.httpdate,
                                'X-Baas-Auth' => "#{public_key}:invalid",
                                'Authorization' => "#{public_key}:#{auth_token}" } }

              it 'invokes the application' do
                make_request

                application.should have_received(:call).twice
              end

              describe 'the response' do

                subject(:response) { make_request; last_response }

                its(:status) { should eq(200) }
                its(['X-Baas-Session-Seed']) { should_not be_empty }

              end
            end
          end

          context 'and the session has timed out' do
            before { Timecop.travel(Angus::Authentication::Provider::DEFAULT_SESSION_TTL + 10) }

            context 'and authentication data missing' do
              let(:session_auth_token) {
                Digest::SHA1.hexdigest("#{session_private_key}\n#{auth_data}")
              }
              let(:headers) { { 'date' => date.httpdate,
                                'X-Baas-Auth' => "#{public_key}:#{session_auth_token}",
                                'Authorization' => nil } }

              it 'does not invoke the application' do
                make_request

                application.should have_received(:call).once
              end

              describe 'the response' do

                subject(:response) { make_request; last_response }

                its(:status) { should eq(419) }

              end
            end

            context 'when valid authentication data' do
              let(:session_auth_token) {
                Digest::SHA1.hexdigest("#{session_private_key}\n#{auth_data}")
              }
              let(:headers) { { 'date' => date.httpdate,
                                'X-Baas-Auth' => "#{public_key}:#{session_auth_token}",
                                'Authorization' => "#{public_key}:#{auth_token}" } }

              it 'invokes the application' do
                make_request

                application.should have_received(:call).twice
              end

              describe 'the response' do

                subject(:response) { make_request; last_response }

                its(:status) { should eq(200) }
                its(['X-Baas-Session-Seed']) { should_not be_empty }

              end
            end

            context 'when invalid authentication data' do
              let(:session_auth_token) {
                Digest::SHA1.hexdigest("#{session_private_key}\n#{auth_data}")
              }
              let(:headers) { { 'date' => date.httpdate,
                                'X-Baas-Auth' => "#{public_key}:#{session_auth_token}",
                                'Authorization' => "#{public_key}:aa#{auth_token}" } }


              it 'does not invoke the application' do
                make_request

                application.should have_received(:call).once
              end

              describe 'the response' do

                subject(:response) { make_request; last_response }

                its(:status) { should eq(401) }

              end
            end
          end

          context 'when valid session authentication headers' do
            let(:session_auth_token) {
              Digest::SHA1.hexdigest("#{session_private_key}\n#{auth_data}")
            }
            let(:headers) { { 'date' => date.httpdate,
                              'X-Baas-Auth' => "#{public_key}:#{session_auth_token}" } }

            it 'invokes the application' do
              make_request

              application.should have_received(:call).twice
            end

            describe 'the response' do

              subject(:response) { make_request; last_response }

              its(:status) { should eq(200) }

            end
          end
        end
      end
    end

  end

end