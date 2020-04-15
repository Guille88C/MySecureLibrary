package com.gcuestab.myscureapplication

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.gcuestab.mycrypt.crypt.MyCrypt
import kotlinx.android.synthetic.main.activity_main.*


class MainActivity : AppCompatActivity() {

    private var encryptedText = ""

    private val myCrypt by lazy {
        MyCrypt()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        bActivityMainEncrypt?.setOnClickListener {
            encryptedText = myCrypt.encrypt(context = this, text = etActivityMain.text.toString())
            tvActivityMain.text = encryptedText
        }

        bActivityMainDecrypt?.setOnClickListener {
            tvActivityMain.text = myCrypt.decrypt(context = this, encryptedText = encryptedText)
        }
    }
}
