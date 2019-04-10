package Leet;

import java.io.*;
import java.util.*;

public class Filter {
    public static void main(String[] arg) throws IOException {
        RuleSets ruleSets = new RuleSets();
        //ruleSets.setReport("Report_10000.txt");
        ruleSets.setRuleSets("RS10.txt", ruleSets.ruleSets);
        //ruleSets.setRuleSets("RS1000.txt", ruleSets.secondRuleSets);
        //ruleSets.check("RS1000.txt");
        //ruleSets.check("PACKAGE.txt");
        //ruleSets.print();
    }
}

class RuleSets extends HashMap {

    public HashMap<Integer, Integer[]> ruleSets;
    //private HashMap<Integer, String[]> originalRuleSets;
    public HashMap<Integer, Integer[]> secondRuleSets;
    private FileWriter report;
    private int redundantRules = 0;

    public RuleSets() {
        this.ruleSets = new HashMap<>();
        this.secondRuleSets = new HashMap<>();
    }

    public void setReport(String path) throws IOException {
        this.report = new FileWriter(path);
    }

    public void setRuleSets(String path, HashMap map) {
        try {
            File file = new File(path);
            BufferedReader br = new BufferedReader(new FileReader(file));
            String line;
            int priority = 0;
            String deny = "DENY";
            System.out.print(String.format("%-15s %-15s %-8s\n", "Source", "Destination", "Action"));

            int x = 0;
            while ((line = br.readLine()) != null) {
                String[] str = line.split(",");
                Integer action;
                if (deny.equals(str[2])) {
                    action = 0;
                } else {
                    action = 1;
                }

                Integer[] rule;
                int[] sourceIpRange = handleIp(str[0]);

                //General IP
                if (sourceIpRange.length == 1) {
                    rule = new Integer[1];
                    rule[0] = action;
                    map.put(0, rule);
                    break;
                }

                //Special IP
                int[] destinationIpRange = handleIp(str[1]);
                rule = new Integer[5];

                Integer[] source = rangeToNumber(sourceIpRange);
                Integer[] destination = rangeToNumber(destinationIpRange);
                int half = source.length;
                for (int i = 0; i < half; i++) {
                    rule[i] = source[i];
                    rule[i + half] = destination[i];
                }
                rule[4] = action;


                if (compareRuleSet(sourceIpRange, destinationIpRange)) {
                    System.out.println(++x);
                    System.out.print(String.format("%-15s %-15s %-8s\n", str[0], str[1], str[2]));
                }

                priority++;
                map.put(priority, rule);
            }

        } catch (IOException e) {
            System.out.println("Please use standard file");
        }
    }

    public void check(String path) {
        try {
            File file = new File(path);
            BufferedReader br = new BufferedReader(new FileReader(file));
            String line;
            int count = 0;
            System.out.print(String.format("%-8s %-8s %-8s %-5s\n", "Rule A", "Action", "Rule B", "Action"));
            while ((line = br.readLine()) != null) {
                String[] str = line.split(",");
                int[] sourceIp = handleIp(str[0]);
                int[] destinationIp = handleIp(str[1]);
                Integer[] source = rangeToNumber(sourceIp);
                Integer[] destination = rangeToNumber(destinationIp);
                compareRuleSet(sourceIp, destinationIp);
                //outputResult(sourceIp, destinationIp, result);
                count++;

                Iterator it = ruleSets.entrySet().iterator();
                while (it.hasNext()) {
                    Map.Entry entry = (Map.Entry) it.next();
                    Integer[] ipRange = (Integer[]) entry.getValue();

                    if (ipRange.length == 1) {
                        continue;
                    }

                    boolean sourceMatch = ((source[0] >= ipRange[0] && source[0] <= ipRange[1])
                            || (source[1] >= ipRange[0] && source[1] <= ipRange[1])
                            || (source[0] <= ipRange[0] && source[1] >= ipRange[1]));
                    boolean destinationMatch = ((destination[0] >= ipRange[2] && destination[0] <= ipRange[3])
                            || (destination[1] >= ipRange[2] && destination[1] <= ipRange[3])
                            || (destination[0] <= ipRange[2] && destination[1] >= ipRange[3]));

                    if (sourceMatch && destinationMatch) {
                        Integer[] intersectionPoint = intersectionPoint(ipRange, source, destination);
                        boolean result = compareTwoSets(intersectionPoint);
                        if (result) {
                            String action1, action2;
                            if (ipRange[4] == 0) {
                                action1 = "DENY";
                                action2 = "ALLOW";
                            } else {
                                action2 = "DENY";
                                action1 = "ALLOW";
                            }

                            break;
                        }
                    }

                }

            }

        } catch (IOException e) {
            System.out.println("Please use standard file");
        }
    }


    private int compare(HashMap map, Integer sourceIp, Integer destinationIp) {
        Iterator it = map.entrySet().iterator();

        while (it.hasNext()) {
            Map.Entry entry = (Map.Entry) it.next();
            Integer[] ipRange = (Integer[]) entry.getValue();

            if (ipRange.length == 1) {
                continue;
            }

            boolean sourceMatch = sourceIp >= ipRange[0] && sourceIp <= ipRange[1];
            boolean destinationMatch = destinationIp >= ipRange[2] && destinationIp <= ipRange[3];

            if (sourceMatch && destinationMatch) {
                return (int) entry.getKey();
            }
        }
        return 0;
    }

//    private void outputResult(int[] sourceIp, int[] destinationIp, int rulePriority) throws IOException {
//        String[] originalRule = originalRuleSets.get(rulePriority);
//
//        String action;
//        if ("DENY".equals(originalRule[2])) {
//            action = "DENY";
//        } else {
//            action = "ALLOW";
//        }
//
//        report.write(String.format("%-20s %-20s %-5s %-20s %-20s %-5s\n", toIpForm(sourceIp), toIpForm(destinationIp), rulePriority, originalRule[0], originalRule[1], action));
//        report.flush();
//
//    }

    private String toIpForm(int[] ipAddress) {
        StringBuilder sb = new StringBuilder();
        int lastIpByte = ipAddress.length - 1;
        for (int i = 0; i < lastIpByte; i++) {
            sb.append(ipAddress[i]);
            sb.append(".");
        }
        sb.append(ipAddress[lastIpByte]);

        return sb.toString();
    }

    private Integer toNumber(int[] ipAddress) {
        Integer number = 0;
        int bit = 256;
        for (int i = 0; i < ipAddress.length; i++) {
            int x = (int) Math.pow(bit, 3 - i);
            number += ipAddress[i] * x;
        }
        return number;
    }

    private int[] intToIp(Integer num) {
        int[] ip = new int[4];
        int bit = 256;
        for (int i = 0; i < ip.length; i++) {
            int x = (int) Math.pow(bit, 3 - i);
            ip[i] = num / x;
            num = num % x;
        }
        return ip;
    }

    private int[] handleIp(String ipAddress) {
        String[] ipPart = ipAddress.split("\\.");
        String[] temp = ipPart[3].split("/");
        ipPart[3] = temp[0];
        int[] ip;
        String symbol = "1.1.1.1/0";

        //General IP
//        if (symbol.equals(ipPart[0])) {
//            ip = new int[1];
//            return ip;
//        }
        if (symbol.equals(ipAddress)) {
            ip = new int[1];
            return ip;
        }

        //IP Range
        int hasSubnet = 2;
        if (temp.length == hasSubnet) {
            ip = ipRange(ipPart, Integer.parseInt(temp[1]));
        }
        //Single IP
        else {
            ip = new int[4];
            for (int i = 0; i < ipPart.length; i++) {
                ip[i] = Integer.parseInt(ipPart[i]);
            }
        }

        return ip;
    }

    private int[] ipRange(String[] ipAddress, int code) {
        int[] ipRange = new int[8];
        int half = ipRange.length / 2;

        int[] subnetMaskCode = subnetMaskCode(code);
        for (int i = 0; i < ipAddress.length; i++) {
            ipRange[i] = Integer.parseInt(ipAddress[i]);
        }
        for (int i = 0; i < half; i++) {
            ipRange[i + half] = ipRange[i] | (~subnetMaskCode[i]) + 256;
            ipRange[i] &= subnetMaskCode[i];
        }

        return ipRange;
    }

    private int[] subnetMaskCode(int code) {
        int maxBit = 32;
        int[] maskCode = new int[4];
        if (code == maxBit) {
            for (int i = 0; i < maskCode.length; i++) {
                maskCode[i] = 255;
            }
            return maskCode;
        }

        int wholeByte = code / 8, partByte = code % 8;
        for (int i = 0; i < wholeByte; i++) {
            maskCode[i] = 255;
        }
        int part = 0;
        while (partByte > 0) {
            part += Math.pow(2, 8 - partByte);
            partByte--;
        }
        maskCode[wholeByte] = part;

        return maskCode;
    }

    public void print() {
        Iterator it = ruleSets.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry entry = (Map.Entry) it.next();
            int key = (int) entry.getKey();
            LinkedList ipRange = (LinkedList) entry.getValue();
            System.out.println(key);
            for (int i = 0; i < ipRange.size(); i++) {
                System.out.print(ipRange.get(i) + "  ");
            }
            System.out.println();
        }
    }


    private Integer[] rangeToNumber(int[] ipRange) {
        int[] startPoint = new int[4], endPoint = new int[4];
        Integer[] numberRange = new Integer[2];
        int half = ipRange.length / 2;
        for (int i = 0; i < half; i++) {
            startPoint[i] = ipRange[i];
            endPoint[i] = ipRange[i + half];
        }
        numberRange[0] = toNumber(startPoint);
        numberRange[1] = toNumber(endPoint);
        return numberRange;
    }

    private boolean compareRuleSet(int[] sourceIp, int[] destinationIp) {
        Iterator it = ruleSets.entrySet().iterator();
        boolean isRedundant = false;
        while (it.hasNext()) {

            Map.Entry entry = (Map.Entry) it.next();
            Integer[] ipRange = (Integer[]) entry.getValue();

            //被检查的范围转数字
            Integer[] checkSource = rangeToNumber(sourceIp);
            Integer[] checkDestination = rangeToNumber(destinationIp);

            if (ipRange.length == 1) {
                continue;
            }

            boolean sourceMatch = ((checkSource[0] >= ipRange[0] && checkSource[0] <= ipRange[1])
                    || (checkSource[1] >= ipRange[0] && checkSource[1] <= ipRange[1])
                    || (checkSource[0] <= ipRange[0] && checkSource[1] >= ipRange[1]));
            boolean destinationMatch = ((checkDestination[0] >= ipRange[2] && checkDestination[0] <= ipRange[3])
                    || (checkDestination[1] >= ipRange[2] && checkDestination[1] <= ipRange[3])
                    || (checkDestination[0] <= ipRange[2] && checkDestination[1] >= ipRange[3]));
            if (sourceMatch && destinationMatch) {
                //交点
                Integer[] intersectionPoint = intersectionPoint(ipRange, checkSource, checkDestination);

                LinkedList<Integer[]> checkPoints = checkPoints(intersectionPoint);
                isRedundant = findRedundant(checkPoints, checkSource, checkDestination);
                if (!isRedundant) {
                    return true;
                }
            }
        }

        if (isRedundant) {
            redundantRules++;
        }

        return false;
    }


    private boolean compareTwoSets(Integer[] intersectionPoint) {
        int result1 = compare(ruleSets, intersectionPoint[0], intersectionPoint[2]);
        int result2 = compare(secondRuleSets, intersectionPoint[0], intersectionPoint[2]);
        Integer action1, action2;

        if (result1 == 0) {
            action1 = ruleSets.get(result1)[0];
        } else {
            action1 = ruleSets.get(result1)[4];
        }

        if (result2 == 0) {
            action2 = secondRuleSets.get(result2)[0];
        } else {
            action2 = secondRuleSets.get(result2)[4];
        }

        if (!action1.equals(action2)) {
            System.out.print(String.format("%-8s %-8s %-8s %-5s\n", result1, action1, result2, action2));
        }
        return !action1.equals(action2);
    }

    private boolean findRedundant(LinkedList<Integer[]> checkPoints, Integer[] checkSource, Integer[] checkDestination) {
        for (Integer[] point : checkPoints) {
            boolean sourceMatch = point[0] >= checkSource[0] && point[0] <= checkSource[1];
            boolean destinationMatch = point[1] >= checkDestination[0] && point[1] <= checkDestination[1];
            if (sourceMatch && destinationMatch) {
                //int[] sourceIp = intToIp(point[0]);
                //int[] destinationIp = intToIp(point[1]);
                int result = compare(ruleSets, point[0], point[1]);

                //new one
                if (result == 0) {
                    return false;
                }
            }

        }
        return true;
    }

    private Integer[] intersectionPoint(Integer[] ipRang, Integer[] checkSource, Integer[] checkDestination) {
        Integer[] source = new Integer[4], destination = new Integer[4];
        int half = 2;
        for (int i = 0; i < half; i++) {
            source[i] = ipRang[i];
            source[i + half] = checkSource[i];
            destination[i] = ipRang[i + half];
            destination[i + half] = checkDestination[i];
        }
        Arrays.sort(source);
        Arrays.sort(destination);
        Integer[] intersectionPoint = new Integer[4];
        for (int i = 0; i < half; i++) {
            intersectionPoint[i] = source[i + 1];
            intersectionPoint[i + half] = destination[i + 1];
        }
        return intersectionPoint;
    }

    private LinkedList<Integer[]> checkPoints(Integer[] intersectionPoint) {
        LinkedList<Integer[]> checkPoints = new LinkedList<>();

        //x+1, w
        Integer[] temp0 = new Integer[2];
        temp0[0] = intersectionPoint[0] + 1;
        temp0[1] = intersectionPoint[2];
        checkPoints.add(temp0);
        //x+1, z
        Integer[] temp1 = new Integer[2];
        temp1[0] = intersectionPoint[0] + 1;
        temp1[1] = intersectionPoint[3];
        checkPoints.add(temp1);
        //x-1, w
        Integer[] temp3 = new Integer[2];
        temp3[0] = intersectionPoint[0] - 1;
        temp3[1] = intersectionPoint[2];
        checkPoints.add(temp3);
        //x-1, z
        Integer[] temp2 = new Integer[2];
        temp2[0] = intersectionPoint[0] - 1;
        temp2[1] = intersectionPoint[3];
        checkPoints.add(temp2);

        //x, w+1
        Integer[] temp4 = new Integer[2];
        temp4[0] = intersectionPoint[0];
        temp4[1] = intersectionPoint[2] + 1;
        checkPoints.add(temp4);
        //x, w-1
        Integer[] temp5 = new Integer[2];
        temp5[0] = intersectionPoint[0];
        temp5[1] = intersectionPoint[2] - 1;
        checkPoints.add(temp5);
        //x, z+1
        Integer[] temp6 = new Integer[2];
        temp6[0] = intersectionPoint[0];
        temp6[1] = intersectionPoint[3] + 1;
        checkPoints.add(temp6);
        //x, z-1
        Integer[] temp7 = new Integer[2];
        temp7[0] = intersectionPoint[0];
        temp7[1] = intersectionPoint[3] - 1;
        checkPoints.add(temp7);

        //y+1, w
        Integer[] temp8 = new Integer[2];
        temp8[0] = intersectionPoint[1] + 1;
        temp8[1] = intersectionPoint[2];
        checkPoints.add(temp8);
        //y+1, z
        Integer[] temp9 = new Integer[2];
        temp9[0] = intersectionPoint[1] + 1;
        temp9[1] = intersectionPoint[3];
        checkPoints.add(temp9);
        //y-1, z
        Integer[] temp10 = new Integer[2];
        temp10[0] = intersectionPoint[1] - 1;
        temp10[1] = intersectionPoint[3];
        checkPoints.add(temp10);
        //y-1, w
        Integer[] temp11 = new Integer[2];
        temp11[0] = intersectionPoint[1] - 1;
        temp11[1] = intersectionPoint[2];
        checkPoints.add(temp11);

        //y, w+1
        Integer[] temp12 = new Integer[2];
        temp12[0] = intersectionPoint[1];
        temp12[1] = intersectionPoint[2] + 1;
        checkPoints.add(temp12);
        //y, w-1
        Integer[] temp13 = new Integer[2];
        temp13[0] = intersectionPoint[1];
        temp13[1] = intersectionPoint[2] - 1;
        checkPoints.add(temp13);
        //y, z+1
        Integer[] temp14 = new Integer[2];
        temp14[0] = intersectionPoint[1];
        temp14[1] = intersectionPoint[3] + 1;
        checkPoints.add(temp14);
        //y, z-1
        Integer[] temp15 = new Integer[2];
        temp15[0] = intersectionPoint[1];
        temp15[1] = intersectionPoint[3] - 1;
        checkPoints.add(temp15);

        return checkPoints;
    }
}
