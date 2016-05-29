/*
Navicat MySQL Data Transfer

Source Server         : localhost_3306
Source Server Version : 50624
Source Host           : localhost:3306
Source Database       : wh_ct4_hgduyingjkhjhjg

Target Server Type    : MYSQL
Target Server Version : 50624
File Encoding         : 65001

Date: 2016-05-25 22:23:16
*/

SET FOREIGN_KEY_CHECKS=0;

-- ----------------------------
-- Table structure for `flag`
-- ----------------------------
DROP TABLE IF EXISTS `flag`;
CREATE TABLE `flag` (
  `tips` varchar(100) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of flag
-- ----------------------------
INSERT INTO `flag` VALUES ('flag is nothere,but I can tell you the flag is xor user\'s password.');
