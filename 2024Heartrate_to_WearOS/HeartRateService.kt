package io.ostendorf.heartratetoweb

//import androidx.appcompat.app.AppCompatActivity

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.os.IBinder
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import com.android.volley.RequestQueue
import com.android.volley.request.StringRequest
import com.android.volley.toolbox.Volley
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.math.roundToInt


class HeartRateService : Service(), SensorEventListener {

    private lateinit var mHeartRateSensor: Sensor
    private lateinit var mSensorManager: SensorManager
    private lateinit var httpQueue: RequestQueue
    private lateinit var preferences: SharedPreferences

    private val CHANNEL_ID = "HeartRateService"

        companion object {
        fun startService(context: Context) {
            val startIntent = Intent(context, HeartRateService::class.java)
            ContextCompat.startForegroundService(context, startIntent)
        }

        fun stopService(context: Context) {
            val stopIntent = Intent(context, HeartRateService::class.java)
            context.stopService(stopIntent)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {

        doSomething()

        createNotificationChannel()

        val notificationIntent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            notificationIntent,
            PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(R.string.notification_title.toString())
            .setContentText(R.string.notification_text.toString())
            .setContentIntent(pendingIntent)
            .build()

        startForeground(1, notification)

        return START_NOT_STICKY

    }

    override fun onBind(intent: Intent?): IBinder? {
        return null
    }

    private fun createNotificationChannel() {
        val serviceChannel = NotificationChannel(
            CHANNEL_ID,
            R.string.notification_channel_title.toString(),
            NotificationManager.IMPORTANCE_DEFAULT
        )

        val manager = getSystemService(NotificationManager::class.java)
        manager!!.createNotificationChannel(serviceChannel)
    }

    private fun doSomething() {

        preferences = this.getSharedPreferences(packageName + "_preferences", MODE_PRIVATE)
        httpQueue = Volley.newRequestQueue(this)

        mSensorManager = getSystemService(Context.SENSOR_SERVICE) as SensorManager
        mHeartRateSensor = mSensorManager.getDefaultSensor(Sensor.TYPE_HEART_RATE)

        startMeasure()

    }

    private fun startMeasure() {
        val sensorRegistered: Boolean = mSensorManager.registerListener(
            this,
            mHeartRateSensor,
            SensorManager.SENSOR_DELAY_FASTEST
        )
        Log.d("Sensor Status:", " Sensor registered: " + (if (sensorRegistered) "yes" else "no"))
        sendStatusToActivity(MainActivity.Config.CONF_SENDING_STATUS_STARTING)
    }

    private fun stopMeasure() {
        mSensorManager.unregisterListener(this)
        sendStatusToActivity(MainActivity.Config.CONF_SENDING_STATUS_NOT_RUNNING)
    }

    override fun onSensorChanged(event: SensorEvent?) {
        val mHeartRateFloat: Float = event!!.values[0]

        val mHeartRate: Int = mHeartRateFloat.roundToInt()
        Log.d("HR: ", mHeartRate.toString())

        sendHeartRate(mHeartRate)
        sendHeartRateToActivity(mHeartRate)
    }

    override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {
        // ignored
    }

    private fun sendHeartRate(heartrate: Int) {

        val mykey = generateAesKey()


        Log.d(" generateAesKey generated key data:", "" )
        //val bytes = mykey.encoded
        //for (b in bytes) {
        //    val st = String.format("%02X", b)
        //    print(st)
        //}
        //Log.d(" generateAesKey generated key data:", "end" )


        val mystring = "$heartrate"
        val messageinput = mystring.toByteArray()
        val heartrate_enc = encrypt(mykey,messageinput)
        val decryptedData = decrypt(mykey, heartrate_enc.iv, heartrate_enc.tag, heartrate_enc.ciphertext)
        //val encrypted = pair.second.toString(Charsets.UTF_8)
        //println("Encrypted data: $encrypted")
        //Log.d(" Encrypted data:", encrypted)
        //println("Decrypted data: $decryptedData")
        Log.d(" myKey data:", mykey.toString())
        Log.d(" Decrypted data:", String(decryptedData))

        val patient_id = "100"
        val patient_id_enc = encrypt(mykey, patient_id.toByteArray())
        val httpUrl = "http://" +
                preferences.getString(
                    MainActivity.Config.CONF_HTTP_HOSTNAME,
                    MainActivity.Config.CONF_HTTP_HOSTNAME_DEFAULT
                ) +
                ":" + preferences.getInt(
            MainActivity.Config.CONF_HTTP_PORT,
            MainActivity.Config.CONF_HTTP_PORT_DEFAULT
        ).toString()

        val httpRequest = object : StringRequest(
            Method.POST,
            httpUrl,
            { response ->
                Log.d("HTTP Reponse: ", response)
                sendStatusToActivity(MainActivity.Config.CONF_SENDING_STATUS_OK)
            },
            {
                Log.e("HTTP Error", it.message.toString())
                sendStatusToActivity(MainActivity.Config.CONF_SENDING_STATUS_ERROR)
            }
        ) {
            override fun getBodyContentType(): String {
                return "application/x-www-form-urlencoded; charset=UTF-8"
            }

            override fun getBody(): ByteArray {
                //val localPData = "rate=$heartrate"+"&patient=$patient_id"
                val localPData = "rate=${heartrate_enc.ciphertext}"+"&rate_iv=${heartrate_enc.iv.toString()}"+"&rate_tag=${heartrate_enc.tag.toString()}"+"&patient=${patient_id_enc.ciphertext}"+"&pid_iv=${patient_id_enc.iv.toString()}"+"&pid_tag=${patient_id_enc.tag.toString()}"+"&mykey=${mykey.toString()}"
                Log.e("local data: ",localPData.toString())
                return localPData.toByteArray(Charsets.UTF_8)
            }
        }

        httpQueue.add(httpRequest)
    }

    override fun onDestroy() {
        stopMeasure()
        super.onDestroy()
    }

    private fun sendHeartRateToActivity(heartrate: Int) {
        val intent = Intent(MainActivity.Config.CONF_BROADCAST_HEARTRATE_UPDATE)
        intent.putExtra("heartrate", heartrate)
        LocalBroadcastManager.getInstance(this).sendBroadcast(intent)
    }

    private fun sendStatusToActivity(status: String) {
        val intent = Intent(MainActivity.Config.CONF_BROADCAST_STATUS)
        intent.putExtra("status", status)
        LocalBroadcastManager.getInstance(this).sendBroadcast(intent)
    }

    private fun generateAesKey(): SecretKey {
        val mysize :Int = 256
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
       // val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES)

        val kgps = KeyGenParameterSpec.Builder("my_aes_key", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(mysize)
            // This is required to be able to provide the IV ourselves
            .setRandomizedEncryptionRequired(false)
            .build()
        keyGenerator.init(kgps)

        //val keyGenerator = KeyGenerator.getInstance("AES")
        //keyGenerator.init( mysize , SecureRandom.getInstanceStrong());

        return keyGenerator.generateKey()
    }

    val TAG_LENGTH = 16

    class EncryptionOutput(val iv: ByteArray,
                           val tag: ByteArray,
                           val ciphertext: ByteArray)

    private fun encrypt(key: SecretKey, message: ByteArray): EncryptionOutput {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv.copyOf()
        val result = cipher.doFinal(message)
        val ciphertext = result.copyOfRange(0, result.size - TAG_LENGTH)
        val tag = result.copyOfRange(result.size - TAG_LENGTH, result.size)
        Log.d(" In encrypt(): iv: ", String(iv))
        Log.d(" In encrypt(): Cipher: ", String(ciphertext))
        Log.d(" In encrypt(): Tag: ", String(tag))

        return EncryptionOutput(iv, tag, ciphertext)
    }

    private fun decrypt(key: SecretKey, iv: ByteArray, tag: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(TAG_LENGTH * 8, iv)
        cipher.init(Cipher.DECRYPT_MODE, key, spec)
        return cipher.doFinal(ciphertext + tag)
    }
}