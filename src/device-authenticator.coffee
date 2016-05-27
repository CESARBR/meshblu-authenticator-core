bcrypt = require 'bcrypt'
_ = require 'lodash'

class DeviceAuthenticator
  @ERROR_DEVICE_ALREADY_EXISTS : 'device already exists'
  @ERROR_DEVICE_NOT_FOUND : 'device not found'
  @ERROR_CANNOT_WRITE_TO_DEVICE : 'cannot write to device'

  constructor: ({@authenticatorUuid, @authenticatorName, @meshbluHttp})->

  buildDeviceUpdate: ({owner, user_id, hashedSecret}) =>
    data = {
      id: user_id
      name: @authenticatorName
      secret: hashedSecret
    }
    signature = @meshbluHttp.sign(data)

    deviceUpdate = {
      owner: owner
    }

    deviceUpdate[@authenticatorUuid] = _.defaults({signature: signature}, data)
    return deviceUpdate

  create: ({query, data, user_id, secret}, callback) =>
    data.discoverWhitelist = [@authenticatorUuid]
    data.configureWhitelist = [@authenticatorUuid]
    data[@authenticatorUuid] ?= {}
    data[@authenticatorUuid].createdAt = new Date
    @insert {query, data}, (error, device) =>
      return callback error if error?
      @writeAuthData {uuid: device.uuid, owner: device.uuid, user_id, secret}, (error) =>
        callback(error, device)

  addAuth: ({query, uuid, user_id, secret}, callback) =>
    @exists {query}, (deviceExists) =>
      return callback new Error DeviceAuthenticator.ERROR_DEVICE_ALREADY_EXISTS if deviceExists
      @meshbluHttp.device uuid, (error, device) =>
        return callback new Error DeviceAuthenticator.ERROR_DEVICE_NOT_FOUND if error?
        @writeAuthData uuid, device.owner, user_id, secret, (error) =>
          callback(error, device)

  writeAuthData: ({uuid, owner, user_id, secret}, callback) =>
     @hashSecret {secret: secret + uuid}, (error, hashedSecret) =>
        return callback error if error?
        updateData = @buildDeviceUpdate({owner, user_id, hashedSecret})
        @update {uuid: uuid, data: updateData}, (error, device) =>
          return callback new Error DeviceAuthenticator.ERROR_CANNOT_WRITE_TO_DEVICE if error?
          callback null, device

  exists: ({query}, callback) =>
    @meshbluHttp.devices query, (error, devices) =>
      return callback error if error?
      devices = _.filter devices, (device) =>
        @verifySignature data: device[@authenticatorUuid]

      callback null, ! _.isEmpty devices

  findVerified: ({query, password}, callback) =>
    projection =
      uuid: true
      "#{@authenticatorUuid}": true
    @meshbluHttp.search query, {projection}, (error, devices) =>
      return callback error if error?
      devices = _.filter devices, (device) =>
        authData = device[@authenticatorUuid]
        return false unless @verifySignature {data: authData}
        return false unless @verifySecret {secret: password + device.uuid, hash: authData.secret}
        return true

      callback null, _.first devices

  hashSecret: ({secret}, callback) =>
    bcrypt.hash secret, 8, callback

  insert: ({query, data}, callback) =>
    @exists {query}, (error, deviceExists) =>
      return callback error if error?
      return callback new Error DeviceAuthenticator.ERROR_DEVICE_ALREADY_EXISTS if deviceExists
      @meshbluHttp.register data, callback

  update: ({uuid, data}, callback) =>
    @meshbluHttp.update uuid, data, callback

  verifySignature: ({data}) =>
    return false unless data?.signature?
    @meshbluHttp.verify _.omit(data, 'signature'), data.signature

  verifySecret: ({secret, hash}) =>
    bcrypt.compareSync secret, hash

module.exports = DeviceAuthenticator
