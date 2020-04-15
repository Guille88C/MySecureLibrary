package com.gcuestab.myscureapplication

import android.content.Context
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.gcuestab.mycrypt.crypt.MyCrypt
import kotlinx.android.synthetic.main.activity_main.*


class MainActivity : AppCompatActivity() {

    private val sharedPreferences by lazy {
        getSharedPreferences("default", Context.MODE_PRIVATE)
    }

    private val sharedEdit by lazy {
        sharedPreferences.edit()
    }

    private val myCrypt by lazy {
        MyCrypt()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        bActivityMainSave?.setOnClickListener {
            val user = etActivityMainUser.text.toString()
            val userEncrypted = myCrypt.encrypt(context = this, text = user)
            sharedEdit.putString(USER, userEncrypted).apply()

            val pass = etActivityMainPass.text.toString()
            val passEncrypted = myCrypt.encrypt(context = this, text = pass)
            sharedEdit.putString(PASS, passEncrypted).apply()

            etActivityMainUser.setText("")
            etActivityMainPass.setText("")
        }

        bActivityMainRestore?.setOnClickListener {
            val userEncrypted = sharedPreferences.getString(USER, "") ?: ""
            val user = myCrypt.decrypt(context = this, encryptedText = userEncrypted)
            etActivityMainUser.setText(user)

            val passEncrypted = sharedPreferences.getString(PASS, "") ?: ""
            val pass = myCrypt.decrypt(context = this, encryptedText = passEncrypted)
            etActivityMainPass.setText(pass)
        }
    }

    companion object {
        private const val USER = "user"
        private const val PASS = "pass"
    }
}
