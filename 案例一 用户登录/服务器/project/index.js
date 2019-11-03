const crypto = require('crypto');
const WXBizDataCrypt = require('./WXBizDataCrypt')

const express = require('express')
const bodyParser = require('body-parser')
const request = require('request')
const app = express()
app.use(bodyParser.json())

const wx = {
    appid: 'wx995bee3b6ce37e97',
    secret: 'c6dc4aeed4173a44a99a8226a62d866f'
}

var db = {
    session: {},
    user: {}
}

app.post('/login', (req, res) => {
    
    console.log('login code: ' + req.body.code)
    var url = 'https://api.weixin.qq.com/sns/jscode2session?appid=' + wx.appid + '&secret=' + wx.secret + '&js_code=' + req.body.code + '&grant_type=authorization_code'
    request(url, (err, response, body) => {
        console.log('session: ' + body)
        var session = JSON.parse(body)
        if(session.openid) {
            var token = 'token_' + new Date().getTime()
            db.session[token] = session
            if(!db.user[session.openid]) {
                db.user[session.openid] = {
                    credit: 100
                }
            }
        }
        res.json({
            token: token
        })
    })
})
app.get('/credit', (req, res) => {
    var session = db.session[req.query.token]
    if(session && db.user[session.openid]) {
        res.json({
            credit: db.user[session.openid].credit
        })
    } else {
        res.json({
            err: '该用户不存在，或未登录。'
        })
    }
})

app.post('/userinfo', (req, res) => {
        var session = db.session[req.query.token]
    console.log('session:' + session)
    if(session) {
        
        var pc = new WXBizDataCrypt(wx.appid, session.session_key)
        var data = pc.decryptData(req.body.encryptedData, req.body.iv)
        console.log('解密后：', data)
        var sha1 = crypto.createHash('sha1')
        sha1.update(req.body.rawData + session.session_key)
        var signature2 = sha1.digest('hex')
        console.log(signature2)
        console.log(req.body.signature)
        res.json({
            pass: signature2 === req.body.signature
        })
    } else {
        res.json({
            err: '该用户不存在，或未登录。'     })
    }
})


app.listen(3000, () => {
    console.log('server running at http://127.0.0.1:3000')
})
