Device = require '../../src/device-authenticator'
bcrypt = require 'bcrypt'

describe 'Device', ->
  describe '->buildDeviceUpdate', ->
    beforeEach ->
      @meshblu = {}
      @meshblu.sign = sinon.stub()
      @dependencies = {meshblu:@meshblu}
      @sut = new Device '1', 'name', @dependencies

    describe 'when called with data', ->
      beforeEach ->
        @sut.buildDeviceUpdate "auuid", '1', "pretendyoucantreadthis"

      it 'should call meshblu.sign', ->
        expect(@meshblu.sign).to.have.been.calledWith {id: '1', name: 'name', secret: 'pretendyoucantreadthis'}

  describe '->create', ->
    beforeEach ->
      @meshblu = sinon.stub()
      @dependencies = {meshblu: @meshblu}
      @sut = new Device 'auth-id', 'authenticator', @dependencies

    describe 'calling exists', ->
      beforeEach ->
        @sut.exists = sinon.spy()
        @sut.create 'google.id': '959', {}, 'secret'

      it 'should call exists', ->
        expect(@sut.exists).to.have.been.calledWith 'google.id' : '959'

    describe 'when exists yields true', ->
      beforeEach (done) ->
        @sut.exists = sinon.stub().yields true
        @sut.insert = sinon.stub().yields new Error @sut.ERROR_DEVICE_ALREADY_EXISTS
        @sut.create 'google.id': '595', {}, 'id', 'secret', (@error) => done()

      it 'should call insert', ->
        expect(@sut.insert).to.have.been.called

      it 'should have a device already exists error', ->
        expect(@error.message).to.equal @sut.ERROR_DEVICE_ALREADY_EXISTS

    describe 'when exists yields false', ->
      beforeEach ->
        @sut.exists = sinon.stub().yields false
        @sut.insert = sinon.spy()
        @sut.create 'google.id': '595', {google:{id: 123}}, 'id', 'secret'

      it 'should call insert', ->
        expect(@sut.insert).to.have.been.calledWith 'google.id': '595', {google:{id: 123}}

    describe 'when exists yields false and insert yields an error', ->
      beforeEach (done) ->
        @sut.exists = sinon.stub().yields false
        @sut.insert = sinon.stub().yields new Error
        @sut.create 'google.id': '595', {}, 'id', 'secret', (@error) => done()

      it 'should have an error', ->
        expect(@error).to.exist

    describe 'when exists yields false and insert yields a device', ->
      beforeEach (done) ->
        @meshblu.sign = sinon.stub().returns 'trust-me'
        @sut.exists = sinon.stub().yields false
        @sut.insert = sinon.stub().yields null, {uuid: 'wobbly-table'}
        @sut.hashSecret = sinon.stub().yields null
        @sut.update = sinon.stub().yields null
        @sut.create 'google.id': '595', {}, 'id', 'secret', (@error) => done()

      it 'should call hashSecret', ->
        expect(@sut.hashSecret).to.have.been.calledWith 'secret' + 'wobbly-table'

    describe 'when exists yields false and insert yields a device and hashSecret yields an error', ->
      beforeEach (done) ->
        @sut.exists = sinon.stub().yields false
        @sut.insert = sinon.stub().yields null, {uuid: 'wobbly-table'}
        @sut.hashSecret = sinon.stub().yields new Error
        @sut.create 'google.id': '595', {}, null, null, (@error) => done()

      it 'should have an error', ->
        expect(@error).to.exist

    describe 'when exists yields false and insert yields a device and hashSecret yields a secret', ->
      beforeEach (done) ->
        @meshblu.sign = sinon.stub().returns 'trust-me'
        @sut.exists = sinon.stub().yields false
        @sut.insert = sinon.stub().yields null, {uuid: 'wobbly-table'}
        @sut.hashSecret = sinon.stub().yields null, '$$$$$$$$$$'
        @sut.update = sinon.stub().yields null
        @sut.create 'google.id': '595', {}, '1', 'secret', (@error, @device) => done()

      it 'should call update', ->
        expect(@sut.update).to.have.been.calledWith {uuid: 'wobbly-table', 'auth-id': {name : 'authenticator', id: '1', secret: '$$$$$$$$$$', signature: 'trust-me'}}

      it 'should yield the device', ->
        expect(@device).to.deep.equal {uuid: 'wobbly-table'}

  describe '->exists', ->
    beforeEach ->
      @meshbludb = {}
      @dependencies = meshbludb: @meshbludb
      @sut = new Device '', '', @dependencies

    describe 'when exists is called', ->
      beforeEach ->
        @meshbludb.findOne = sinon.spy()
        @sut.exists {'google.id': '123'}

      it 'should call findOne with query', ->
        expect(@meshbludb.findOne).to.have.been.calledWith 'google.id': '123'

    describe 'when findOne yields a device', ->
      beforeEach (done) ->
        @meshbludb.findOne = sinon.stub().yields null, uuid: 'label-maker'
        @sut.exists 'google.id' : '12350', (@exists) => done()

      it 'should have an device', ->
        expect(@exists).to.be.true

    describe 'when exists yields nothing', ->
      beforeEach (done) ->
        @meshbludb.findOne = sinon.stub().yields null, null
        @sut.exists 'google.id' : '12350', (@exists) => done()

      it 'should not have an device', ->
        expect(@exists).to.be.false

  describe '->insert', ->
    beforeEach ->
      @meshbludb = {}
      @meshbludb.insert = sinon.stub()
      @meshbludb.findOne = sinon.stub().yields()
      @dependencies = {meshbludb:@meshbludb}
      @sut = new Device '', '', @dependencies

    describe 'when insert is called', ->
      beforeEach (done) ->
        @meshbludb.insert.yields null, {}
        @sut.exists = sinon.stub().yields false
        @sut.insert {'something':'tall'}, {'pen':'sharpie'}, (@error, @device) => done()

      it 'should call exists', ->
        expect(@sut.exists).to.have.been.called

      it 'should call meshbludb.insert', ->
        expect(@meshbludb.insert).to.have.been.calledWith {'pen': 'sharpie'}

      it 'should yield a device', ->
        expect(@device).to.exist

    describe 'when insert is called with a different device', ->
      beforeEach ->
        @sut.insert {'something':'black'}, {'skinny': 'stick'}

      it 'should call meshbludb.insert', ->
        expect(@meshbludb.insert).to.have.been.calledWith {'skinny': 'stick'}

  describe '->hashSecret', ->
    beforeEach ->
      @sut = new Device {}

    describe 'when hashSecret is called', ->
      beforeEach (done) ->
        @sut.hashSecret null, (@error) => done()

      it 'should yield an error', ->
        expect(@error).to.exist

    describe 'when bcryptn', ->
      beforeEach (done) ->
        @sut.hashSecret 'shhh', (@error, @hashedSecret) => done()

      it 'should yield a bcrypted secret', ->
        expect(bcrypt.compareSync('shhh', @hashedSecret)).to.be.true

  describe '->update', ->
    beforeEach ->
      @meshbludb = {}
      @meshbludb.update = sinon.stub()
      @dependencies = {meshbludb:@meshbludb}
      @sut = new Device '', '', @dependencies

    describe 'when update yields an error', ->
      beforeEach (done) ->
        @meshbludb.update.yields new Error
        @sut.update {}, (@error) => done()

      it 'should yield an error', ->
        expect(@error).to.exist

    describe 'when update is called', ->
      beforeEach (done) ->
        @meshbludb.update.yields null
        @sut.update {some: 'stuff'}, (@error) => done()

      it 'should get called with stuff', ->
        expect(@meshbludb.update).to.have.been.calledWith {some: 'stuff'}

  describe '->verifySignature', ->
    beforeEach ->
      @meshblu = {}
      @meshblu.verify = sinon.spy()
      @dependencies = {meshblu: @meshblu}
      @sut = new Device '', '', @dependencies

    describe 'when called', ->
      beforeEach ->
        @sut.verifySignature id: 'foo', signature: 'this-is-my-rifle'

      it 'should meshblu.verify', ->
        expect(@meshblu.verify).to.have.been.calledWith {id: 'foo'}, 'this-is-my-rifle'

    describe 'when called with a different device', ->
      beforeEach ->
        @sut.verifySignature id: 'bar', signature: 'this-is-my-gun'

      it 'should meshblu.verify', ->
        expect(@meshblu.verify).to.have.been.calledWith {id: 'bar'}, 'this-is-my-gun'

  describe '->findVerified', ->
    beforeEach ->
      @meshbludb = {}
      @dependencies = meshbludb: @meshbludb
      @sut = new Device 'auth-id', '', @dependencies

    describe 'when find yields an error', ->
      beforeEach (done) ->
        @meshbludb.find = sinon.stub().yields new Error
        @sut.findVerified {}, 'password', (@error) => done()

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
        @meshbludb.find = sinon.stub().yields null, devices
        @sut.verifySignature = sinon.stub().returns true
        @sut.verifySecret = sinon.stub().returns false
        @sut.findVerified {something: 'important'}, 'password', (error, @device) => done()

      it 'should call meshblu.find', ->
        expect(@meshbludb.find).to.have.been.calledWith {something : 'important'} 

      it 'should call verifySignature', ->
        expect(@sut.verifySignature).to.have.been.calledWith signature: 2, secret: '######'

      it 'should call verifySecret', ->
        expect(@sut.verifySecret).to.have.been.calledWith 'password' + 1, '######'

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
        @meshbludb.find = sinon.stub().yields null, devices
        @sut.verifySignature = sinon.stub().returns true
        @sut.verifySecret = sinon.stub().returns true
        @sut.findVerified {something: 'less-important'}, 'password', (error, @device) => done()

      it 'should call meshblu.find', ->
        expect(@meshbludb.find).to.have.been.calledWith {something : 'less-important'}

      it 'should call verifySignature', ->
        expect(@sut.verifySignature).to.have.been.calledWith signature: 8, secret: '######'

      it 'should call verifySecret', ->
        expect(@sut.verifySecret).to.have.been.calledWith 'password' + 7, '######'

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
        @meshbludb.find = sinon.stub().yields null, devices
        @sut.verifySignature = sinon.stub().returns false
        @sut.verifySecret = sinon.stub().returns false
        @sut.findVerified {something: 'less-important'}, 'password' + 7, (error, @device) => done()

      it 'should call meshblu.find', ->
        expect(@meshbludb.find).to.have.been.calledWith {something : 'less-important'}

      it 'should call verifySignature', ->
        expect(@sut.verifySignature).to.have.been.calledWith signature: 8, secret:'######'

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
        @meshbludb.find = sinon.stub().yields null, devices
        @sut.verifySignature = sinon.stub().returns true
        @sut.verifySecret = sinon.stub().returns true
        @sut.findVerified {something: 'more-important'}, 'password', (error, @device) => done()

      it 'should call meshblu.find', ->
        expect(@meshbludb.find).to.have.been.calledWith {something : 'more-important'}

      it 'should call verifySignature', ->
        expect(@sut.verifySignature).to.have.been.calledWith signature: 5, secret: '######'

      it 'should call verifySecret', ->
        expect(@sut.verifySecret).to.have.been.calledWith 'password' + 4, '######'

      it 'should have one device', ->
        expect(@device).to.deep.equal uuid: 4, 'auth-id': signature: 5, secret: '######'

  describe '->verifySecret', ->
    beforeEach ->
      @sut = new Device '', ''

    describe 'when called with valid secret', ->
      beforeEach ->
        @result = @sut.verifySecret 'secret', bcrypt.hashSync('secret', 8)

      it 'should return true', ->
        expect(@result).to.be.true

    describe 'when called with invalid secret', ->
      beforeEach ->
        @result = @sut.verifySecret 'secret', bcrypt.hashSync('not-correct-secret', 8)

      it 'should return false', ->
        expect(@result).to.be.false
      

