DeviceAuthenticator = require '../../src/device-authenticator'
bcrypt = require 'bcrypt'

describe 'DeviceAuthenticator', ->
  beforeEach ->
    @meshbluHttp =
      sign: sinon.stub()
      devices: sinon.stub()
      register: sinon.stub()
      update: sinon.stub()
      verify: sinon.stub()

  describe '->buildDeviceUpdate', ->
    beforeEach ->
      authenticatorUuid = '1'
      authenticatorName = 'name'
      @sut = new DeviceAuthenticator {authenticatorUuid, authenticatorName, @meshbluHttp}

    describe 'when called with data', ->
      beforeEach ->
        @result = @sut.buildDeviceUpdate {deviceUuid: "auuid", owner: "auuid", user_id: '1', hashedSecret: "pretendyoucantreadthis"}

      it 'should call meshblu.sign', ->
        expect(@meshbluHttp.sign).to.have.been.calledWith {id: '1', name: 'name', secret: 'pretendyoucantreadthis'}

      it 'should set the owner', ->
        expect(@result.owner).to.equal "auuid"

  describe '->create', ->
    beforeEach ->
      authenticatorUuid = 'auth-id'
      authenticatorName = 'authenticator'
      @sut = new DeviceAuthenticator {authenticatorUuid, authenticatorName, @meshbluHttp}

    describe 'calling exists', ->
      beforeEach ->
        @sut.exists = sinon.spy()
        @sut.create {query: {'google.id': '959'}, data: {}, secret: 'secret'}

      it 'should call exists', ->
        expect(@sut.exists).to.have.been.calledWith query: {'google.id' : '959'}

    describe 'when exists yields true', ->
      beforeEach (done) ->
        @sut.exists = sinon.stub().yields true
        @sut.insert = sinon.stub().yields new Error DeviceAuthenticator.ERROR_DEVICE_ALREADY_EXISTS
        @sut.create {query: {'google.id': '595'}, data: {}, user_id: 'id', secret: 'secret'}, (@error) => done()

      it 'should call insert', ->
        expect(@sut.insert).to.have.been.calledWith {query: {'google.id': '595'}, data: { configureWhitelist: ["auth-id"], discoverWhitelist: ["auth-id"] }}

      it 'should have a device already exists error', ->
        expect(@error.message).to.equal DeviceAuthenticator.ERROR_DEVICE_ALREADY_EXISTS

    describe 'when exists yields false', ->
      beforeEach ->
        @sut.exists = sinon.stub().yields false
        @sut.insert = sinon.spy()
        @sut.create {query: {'google.id': '595'}, data: {google:{id: 123}}, user_id: 'id', secret: 'secret'}

      it 'should call insert', ->
        device = { google:{id: 123}, configureWhitelist: ["auth-id"], discoverWhitelist: ["auth-id"]  }
        expect(@sut.insert).to.have.been.calledWith {query: {'google.id': '595'}, data: device}

    describe 'when exists yields false and insert yields an error', ->
      beforeEach (done) ->
        @sut.exists = sinon.stub().yields false
        @sut.insert = sinon.stub().yields new Error
        @sut.create {query: {'google.id': '595'}, data: {}, user_id: 'id', secret: 'secret'}, (@error) => done()

      it 'should have an error', ->
        expect(@error).to.exist

    describe 'when exists yields false and insert yields a device', ->
      beforeEach (done) ->
        @meshbluHttp.sign = sinon.stub().returns 'trust-me'
        @sut.exists = sinon.stub().yields false
        @sut.insert = sinon.stub().yields null, {uuid: 'wobbly-table'}
        @sut.hashSecret = sinon.stub().yields null
        @sut.update = sinon.stub().yields null
        @sut.create {query: {'google.id': '595'}, data: {}, user_id: 'id', secret: 'secret'}, (@error) => done()

      it 'should call hashSecret', ->
        expect(@sut.hashSecret).to.have.been.calledWith secret: 'secret' + 'wobbly-table'

    describe 'when exists yields false and insert yields a device and hashSecret yields an error', ->
      beforeEach (done) ->
        @sut.exists = sinon.stub().yields false
        @sut.insert = sinon.stub().yields null, {uuid: 'wobbly-table'}
        @sut.hashSecret = sinon.stub().yields new Error
        @sut.create {query: {'google.id': '595'}, data: {}, user_id: null, secret: null}, (@error) => done()

      it 'should have an error', ->
        expect(@error).to.exist

    describe 'when exists yields false and insert yields a device and hashSecret yields a secret', ->
      beforeEach (done) ->
        @meshbluHttp.sign = sinon.stub().returns 'trust-me'
        @sut.exists = sinon.stub().yields false
        @sut.insert = sinon.stub().yields null, {uuid: 'wobbly-table'}
        @sut.hashSecret = sinon.stub().yields null, '$$$$$$$$$$'
        @sut.update = sinon.stub().yields null
        @sut.create {query: {'google.id': '595'}, data: {}, user_id: '1', secret: 'secret'}, (@error, @device) => done()

      it 'should call update', ->
        expect(@sut.update).to.have.been.calledWith data: {uuid: 'wobbly-table', owner: 'wobbly-table', 'auth-id': {name : 'authenticator', id: '1', secret: '$$$$$$$$$$', signature: 'trust-me'}}

      it 'should yield the device', ->
        expect(@device).to.deep.equal {uuid: 'wobbly-table'}

  describe '->exists', ->
    beforeEach ->
      authenticatorUuid = '1'
      authenticatorName = 'name'
      @sut = new DeviceAuthenticator {authenticatorUuid, authenticatorName, @meshbluHttp}

    describe 'when exists is called', ->
      beforeEach ->
        @sut.exists query: {'google.id': '123'}

      it 'should call findOne with query', ->
        expect(@meshbluHttp.devices).to.have.been.calledWith 'google.id': '123'

    describe 'when findOne yields a device', ->
      beforeEach (done) ->
        @meshbluHttp.devices.yields null, [uuid: 'label-maker']
        @sut.exists query: {'google.id' : '12350'}, (error, @exists) => done error

      it 'should have an device', ->
        expect(@exists).to.be.true

    describe 'when exists yields nothing', ->
      beforeEach (done) ->
        @meshbluHttp.devices.yields null, null
        @sut.exists query: {'google.id' : '12350'}, (error, @exists) => done error

      it 'should not have an device', ->
        expect(@exists).to.be.false

    describe 'when exists yields an empty array', ->
      beforeEach (done) ->
        @meshbluHttp.devices.yields null, []
        @sut.exists query: {'google.id' : '12350'}, (error, @exists) => done error

      it 'should not have an device', ->
        expect(@exists).to.be.false

    describe 'when exists yields an error', ->
      beforeEach (done) ->
        @meshbluHttp.devices.yields new Error
        @sut.exists query: {'google.id' : '12350'}, (@error, @exists) => done()

      it 'should have an error', ->
        expect(@error).to.exist

  describe '->insert', ->
    beforeEach ->
      authenticatorUuid = '1'
      authenticatorName = 'name'
      @sut = new DeviceAuthenticator {authenticatorUuid, authenticatorName, @meshbluHttp}

    describe 'when insert is called', ->
      beforeEach (done) ->
        @meshbluHttp.register.yields null, {}
        @sut.exists = sinon.stub().yields null, false
        @sut.insert query: {'something':'tall'}, data: {'pen':'sharpie'}, (error, @device) => done error

      it 'should call exists', ->
        expect(@sut.exists).to.have.been.calledWith query: {'something': 'tall'}

      it 'should call meshbluHttp.register', ->
        expect(@meshbluHttp.register).to.have.been.calledWith {'pen': 'sharpie'}

      it 'should yield a device', ->
        expect(@device).to.exist

    describe 'when insert is called with a different device', ->
      beforeEach ->
        @sut.exists = sinon.stub().yields null, false
        @sut.insert query: {'something':'black'}, data: {'skinny': 'stick'}

      it 'should call meshbluHttp.insert', ->
        expect(@meshbluHttp.register).to.have.been.calledWith {'skinny': 'stick'}

  describe '->hashSecret', ->
    beforeEach ->
      @sut = new DeviceAuthenticator {}

    describe 'when hashSecret is called', ->
      beforeEach (done) ->
        @sut.hashSecret secret: null, (@error) => done()

      it 'should yield an error', ->
        expect(@error).to.exist

    describe 'when bcryptn', ->
      beforeEach (done) ->
        @sut.hashSecret secret: 'shhh', (@error, @hashedSecret) => done()

      it 'should yield a bcrypted secret', ->
        expect(bcrypt.compareSync('shhh', @hashedSecret)).to.be.true

  describe '->update', ->
    beforeEach ->
      authenticatorUuid = '1'
      authenticatorName = 'name'
      @sut = new DeviceAuthenticator {authenticatorUuid, authenticatorName, @meshbluHttp}

    describe 'when update yields an error', ->
      beforeEach (done) ->
        @meshbluHttp.update.yields new Error
        @sut.update data: {}, (@error) => done()

      it 'should yield an error', ->
        expect(@error).to.exist

    describe 'when update is called', ->
      beforeEach (done) ->
        @meshbluHttp.update.yields null
        @sut.update uuid: 'hi!', data: {uuid: 'hi!', some: 'stuff'}, (error) => done error

      it 'should get called with stuff', ->
        expect(@meshbluHttp.update).to.have.been.calledWith 'hi!', {some: 'stuff', uuid: 'hi!

        '}

  describe '->verifySignature', ->
    beforeEach ->
      authenticatorUuid = '1'
      authenticatorName = 'name'
      @sut = new DeviceAuthenticator {authenticatorUuid, authenticatorName, @meshbluHttp}

    describe 'when called', ->
      beforeEach ->
        @sut.verifySignature data: {id: 'foo', signature: 'this-is-my-rifle'}

      it 'should meshblu.verify', ->
        expect(@meshbluHttp.verify).to.have.been.calledWith {id: 'foo'}, 'this-is-my-rifle'

    describe 'when called with a different device', ->
      beforeEach ->
        @sut.verifySignature data: {id: 'bar', signature: 'this-is-my-gun'}

      it 'should meshblu.verify', ->
        expect(@meshbluHttp.verify).to.have.been.calledWith {id: 'bar'}, 'this-is-my-gun'

  describe '->findVerified', ->
    beforeEach ->
      authenticatorUuid = 'auth-id'
      authenticatorName = 'auth-id'
      @sut = new DeviceAuthenticator {authenticatorUuid, authenticatorName, @meshbluHttp}

    describe 'when find yields an error', ->
      beforeEach (done) ->
        @meshbluHttp.devices.yields new Error
        @sut.findVerified query: {}, password: 'password', (@error) => done()

      it 'should yield an error', ->
        expect(@error).to.exist

    describe 'when it finds one device with a valid signature and invalid secret', ->
      beforeEach (done) ->
        devices = [
          uuid: 1,
          'auth-id':
            signature: 2,
            secret: '######'
        ]
        @meshbluHttp.devices.yields null, devices
        @sut.verifySignature = sinon.stub().returns true
        @sut.verifySecret = sinon.stub().returns false
        @sut.findVerified query: {something: 'important'}, password: 'password', (error, @device) => done()

      it 'should call meshblu.devices', ->
        expect(@meshbluHttp.devices).to.have.been.calledWith {something : 'important'}

      it 'should call verifySignature', ->
        expect(@sut.verifySignature).to.have.been.calledWith data: {signature: 2, secret: '######'}


      it 'should call verifySecret', ->
        expect(@sut.verifySecret).to.have.been.calledWith secret: 'password' + 1, hash: '######'

      it 'should have one device', ->
        expect(@device).to.not.exist

    describe 'when it finds one device with a valid signature and valid secret', ->
      beforeEach (done) ->
        devices = [
          uuid: 7,
          'auth-id':
            signature: 8,
            secret: '######'
        ]
        @meshbluHttp.devices.yields null, devices
        @sut.verifySignature = sinon.stub().returns true
        @sut.verifySecret = sinon.stub().returns true
        @sut.findVerified query: {something: 'less-important'}, password: 'password', (error, @device) => done()

      it 'should call meshblu.find', ->
        expect(@meshbluHttp.devices).to.have.been.calledWith {something : 'less-important'}

      it 'should call verifySignature', ->
        expect(@sut.verifySignature).to.have.been.calledWith data: {signature: 8, secret: '######'}

      it 'should call verifySecret', ->
        expect(@sut.verifySecret).to.have.been.calledWith secret: 'password' + 7, hash: '######'

      it 'should have one device', ->
        expect(@device).to.deep.equal uuid: 7, 'auth-id': signature: 8, secret: '######'

    describe 'when it finds one device with a invalid signature', ->
      beforeEach (done) ->
        devices = [
          uuid: 7,
          'auth-id':
            signature: 8,
            secret: '######'
        ]
        @meshbluHttp.devices.yields null, devices
        @sut.verifySignature = sinon.stub().returns false
        @sut.verifySecret = sinon.stub().returns false
        @sut.findVerified query: {something: 'less-important'}, password: 'password' + 7, (error, @device) => done()

      it 'should call meshblu.find', ->
        expect(@meshbluHttp.devices).to.have.been.calledWith {something : 'less-important'}

      it 'should call verifySignature', ->
        expect(@sut.verifySignature).to.have.been.calledWith data: {signature: 8, secret:'######'}

      it 'should call verifySecret', ->
        expect(@sut.verifySecret).to.not.have.been.called

      it 'should have one device', ->
        expect(@device).to.not.exist

    describe 'when it finds a different valid device', ->
      beforeEach (done) ->
        devices = [
          uuid: 4,
          'auth-id':
            signature: 5,
            secret: '######'
        ]
        @meshbluHttp.devices.yields null, devices
        @sut.verifySignature = sinon.stub().returns true
        @sut.verifySecret = sinon.stub().returns true
        @sut.findVerified query: {something: 'more-important'}, password: 'password', (error, @device) => done()

      it 'should call meshblu.find', ->
        expect(@meshbluHttp.devices).to.have.been.calledWith {something : 'more-important'}

      it 'should call verifySignature', ->
        expect(@sut.verifySignature).to.have.been.calledWith data: {signature: 5, secret: '######'}

      it 'should call verifySecret', ->
        expect(@sut.verifySecret).to.have.been.calledWith secret: 'password' + 4, hash: '######'

      it 'should have one device', ->
        expect(@device).to.deep.equal uuid: 4, 'auth-id': signature: 5, secret: '######'

  describe '->verifySecret', ->
    beforeEach ->
      @sut = new DeviceAuthenticator '', ''

    describe 'when called with valid secret', ->
      beforeEach ->
        @result = @sut.verifySecret secret: 'secret', hash: bcrypt.hashSync('secret', 8)

      it 'should return true', ->
        expect(@result).to.be.true

    describe 'when called with invalid secret', ->
      beforeEach ->
        @result = @sut.verifySecret secret: 'secret', hash: bcrypt.hashSync('not-correct-secret', 8)

      it 'should return false', ->
        expect(@result).to.be.false
