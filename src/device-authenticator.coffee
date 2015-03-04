bcrypt = require 'bcrypt'
_ = require 'lodash'

class DeviceAuthenticator

  ERROR_DEVICE_ALREADY_EXISTS : 'device already exists'

  constructor: (@authenticatorUuid, @authenticatorName, dependencies={})->
    @meshbludb = dependencies.meshbludb
    @meshblu = dependencies.meshblu

  buildDeviceUpdate: (deviceUuid, user_id, hashedSecret) =>
    data = {
      id: user_id
      name: @authenticatorName
      secret: hashedSecret
    }
    signature = @meshblu.sign(data)
    deviceUpdate = {
      uuid: deviceUuid
    }
    deviceUpdate[@authenticatorUuid] = _.defaults({signature: signature}, data)
    return deviceUpdate

  create: (query, data, user_id, secret, callback=->) =>
    @insert query, data, (error, device) =>
      return callback error if error?
      @hashSecret secret + device.uuid, (error, hashedSecret) =>
        return callback error if error?
        updateData = @buildDeviceUpdate(device.uuid, user_id, hashedSecret)
        @update updateData, (error) =>
          callback error, device

  exists: (query, callback=->) =>
    @meshbludb.findOne query, (error, device) =>
      callback device?

  findVerified: (query, password, callback=->)=>
    @meshbludb.find query, (error, devices=[]) =>
      return callback error if error?
      devices = _.filter devices, (device) =>
        return false unless @verifySignature device
        return false unless @verifySecret password + device.uuid, device.secret
        return true

      callback null, _.first devices

  hashSecret: (secret, callback=->) =>
    bcrypt.hash secret, 8, callback

  insert: (query, data, callback=->) =>
    @exists query, (deviceExists) =>
      return callback new Error @ERROR_DEVICE_ALREADY_EXISTS if deviceExists 
      @meshbludb.insert data, callback

  update: (data, callback=->) =>
    @meshbludb.update data, callback

  verifySignature: (data) =>
    @meshblu.verify _.omit(data, 'signature'), data.signature

  verifySecret: (secret, hash) =>
    bcrypt.compareSync secret, hash 

module.exports = DeviceAuthenticator
