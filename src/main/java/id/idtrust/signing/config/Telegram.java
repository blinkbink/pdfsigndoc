//package com.digisign.kms.config;
//
//import com.digisign.kms.util.Description;
//import com.digisign.kms.util.LogSystem;
//import com.github.kshashov.telegram.api.TelegramMvcController;
//import com.pengrad.telegrambot.TelegramBot;
//import com.pengrad.telegrambot.request.SendMessage;
//
//public class Telegram implements TelegramMvcController {
//
//    public Boolean Send(String message) {
//        Description ds = new Description();
//        if(ds.notification)
//        {
//            try {
//                TelegramBot bot = new TelegramBot(getToken());
//                bot.execute(new SendMessage(213382980, "[KMS API], \n" + message));
//            } catch (Exception e) {
//                e.printStackTrace();
//                LogSystem.error("Failed send telegram message " + e.toString());
//                return false;
//            }
//        }
//
//        return true;
//    }
//
//    @Override
//    public String getToken() {
//        return "912934463:AAGOhuRQyFtd5huj0mqsOjkdR8IARrdREYE";
//    }
//}