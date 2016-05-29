/*
Navicat MySQL Data Transfer

Source Server         : localhost_3306
Source Server Version : 50624
Source Host           : localhost:3306
Source Database       : web_sqli

Target Server Type    : MYSQL
Target Server Version : 50624
File Encoding         : 65001

Date: 2016-05-25 22:23:05
*/

SET FOREIGN_KEY_CHECKS=0;

-- ----------------------------
-- Table structure for `article`
-- ----------------------------
DROP TABLE IF EXISTS `article`;
CREATE TABLE `article` (
  `id` int(11) NOT NULL,
  `title` varchar(256) DEFAULT NULL,
  `content` varchar(256) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of article
-- ----------------------------
INSERT INTO `article` VALUES ('0', null, ' of the will, a quality of the imagination, a vigor of the emotions; it is the freshness of the deep springs of life.');
INSERT INTO `article` VALUES ('1', 'Companionship of Books', 'Companionship of Books | A man may usually be known by the books he reads as well as by the company he keeps; for there is a companionship of books as well as of men; and one should always live in the best company, whether it be of books or of men.');
INSERT INTO `article` VALUES ('2', 'If I Rest, I Rust', 'The significant inscription found on an old key---\\x93If I rest, I rust\\x94---would be an excellent motto for those who are afflicted with the slightest bit of idleness. Even the most industrious person might adopt it with advantage to serve as a reminder ');
INSERT INTO `article` VALUES ('3', 'Three Days to See', 'All of us have read thrilling stories in which the hero had only a limited and specified time to live. Sometimes it was as long as a year, sometimes as short as 24 hours. But always we were nterested in discovering just how the doomed hero chose to spend h');
INSERT INTO `article` VALUES ('4', 'Youth', 'Youth is not a time of life; it is a state of mind; it is not a matter of rosy cheeks, red lips and supple knees; it is a matter of the will, a quality of the imagination, a vigor of the emotions; it is the freshness of the deep springs of life.');

-- ----------------------------
-- Table structure for `flag`
-- ----------------------------
DROP TABLE IF EXISTS `flag`;
CREATE TABLE `flag` (
  `flag` varchar(256) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of flag
-- ----------------------------
INSERT INTO `flag` VALUES ('Bool Shit! flag is not here...');

-- ----------------------------
-- Table structure for `users`
-- ----------------------------
DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `pwd` varchar(256) DEFAULT NULL,
  `name` varchar(256) DEFAULT NULL,
  `email` varchar(256) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of users
-- ----------------------------
INSERT INTO `users` VALUES ('962012d09b8170d912f0669f6d7d9d07', 'admin', 'admin@whctf.com');
INSERT INTO `users` VALUES ('8FC63BC4337CD4B5F70577118BB69FE8', 'user1', 'user1@whctf.com');
INSERT INTO `users` VALUES ('6a3fba70c97c880679a740669ddd5ca3', 'user2', 'user2@whctf.com');
